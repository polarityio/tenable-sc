'use strict';

const Bottleneck = require('bottleneck/es5');
const request = require('postman-request');
const _ = require('lodash');
const fp = require('lodash/fp');
const config = require('./config/config');
const { version: packageVersion } = require('./package.json');
const fs = require('fs');
const { DateTime } = require('luxon');

let Logger;
let requestWithDefaults;
let ipBlocklistRegex = null;

const MAX_ENTITY_LENGTH = 100;
const IGNORED_IPS = new Set(['127.0.0.1', '255.255.255.255', '0.0.0.0']);

let limiter = null;

const USER_AGENT = `polarity-tenablesc-integration-v${packageVersion}`;

const NodeCache = require('node-cache');
const tokenCache = new NodeCache({
  stdTTL: 1000 * 1000
});

const _setupLimiter = (options) => {
  limiter = new Bottleneck({
    maxConcurrent: fp.parseInt(10, options.maxConcurrent), // no more than options.maxConcurrent lookups can be running at single time
    highWater: 100, // no more than 100 lookups can be queued up
    strategy: Bottleneck.strategy.OVERFLOW,
    minTime: fp.parseInt(10, options.minTime) // don't run lookups faster than 1 every options.minTime ms
  });
};

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function startup(logger) {
  let defaults = {};
  Logger = logger;

  const { cert, key, ca, passphrase, proxy, rejectUnauthorized } = config.request;

  if (typeof cert === 'string' && cert.length > 0) {
    defaults.cert = fs.readFileSync(cert);
  }

  if (typeof key === 'string' && key.length > 0) {
    defaults.key = fs.readFileSync(key);
  }

  if (typeof ca === 'string' && ca.length > 0) {
    defaults.ca = fs.readFileSync(ca);
  }

  if (typeof passphrase === 'string' && passphrase.length > 0) {
    defaults.passphrase = passphrase;
  }

  if (typeof proxy === 'string' && proxy.length > 0) {
    defaults.proxy = proxy;
  }

  if (typeof rejectUnauthorized === 'boolean') {
    defaults.rejectUnauthorized = rejectUnauthorized;
  }

  defaults.headers = {
    'User-Agent': USER_AGENT
  };

  requestWithDefaults = request.defaults(defaults);
}

const getTokenCacheKey = (options) => options.apiKey + options.apiSecret;
const statusCodeIsInvalid = (statusCode) =>
  [200, 404, 202].every((validStatusCode) => statusCode !== validStatusCode);

function getAuthToken({ url: tenableScUrl, userName, password, ...options }, callback) {
  let cacheKey = getTokenCacheKey(options);

  requestWithDefaults(
    {
      method: 'POST',
      uri: `${tenableScUrl}/rest/token`,
      body: {
        username: userName,
        password
      },
      json: true
    },
    (err, resp, body) => {
      if (err) {
        callback({
          detail: err.code ? `Network Error: ${err.code}` : 'Network error encountered',
          err
        });
        return;
      }

      Logger.trace({ resp }, 'Result of token lookup');

      if (resp.statusCode != 200) {
        callback({
          detail: `Unexpected status code (${resp.statusCode}) received. ${
            body && body.error_msg ? body.error_msg : ''
          }`,
          body,
          statusCode: resp.statusCode
        });
        return;
      }

      let cookie = resp.headers['set-cookie'][1];

      if (typeof cookie === undefined) {
        callback({
          detail: `Response did not include expected cookie`,
          body,
          statusCode: resp.statusCode
        });
        return;
      }

      tokenCache.set(cacheKey, { cookie, token: body.response.token });

      Logger.trace({ tokenCache }, 'Checking TokenCache');

      callback(null, { cookie, token: body.response.token });
    }
  );
}

const parseErrorToReadableJSON = (error) =>
    JSON.parse(JSON.stringify(error, Object.getOwnPropertyNames(error)));

function doLookup(entities, options, cb) {
  try {
    const lookupResults = [];
    const errors = [];
    const blockedEntities = [];
    let numConnectionResets = 0;
    let numThrottled = 0;
    let hasValidIndicator = false;

    if (!limiter) _setupLimiter(options);

    Logger.debug(entities);

    getAuthToken(options, (err, token) => {
      try {
        if (err) {
          Logger.error(err, 'Error getting auth token');
          cb({
            detail: err.detail ? err.detail : 'Unable to authenticate to Tenable',
            err
          });
          return;
        }

        Logger.trace({ token }, 'Retrieved Token');

        let { cookie } = token;
        let cookieJar = request.jar();
        cookieJar.setCookieSync(cookie, options.url);

        Logger.trace({ token }, 'what does the token look like in doLookup');

        entities.forEach((entity) => {
          if (!_isInvalidEntity(entity) && !_isEntityBlocklisted(entity, options)) {
            hasValidIndicator = true;

            limiter.submit(
              _fetchApiData,
              entity,
              token,
              cookieJar,
              options,
              (err, result) => {
                const maxRequestQueueLimitHit =
                  ((err === null || typeof err === 'undefined') && _.isEmpty(result)) ||
                  (err && err.message === 'This job has been dropped by Bottleneck');
                const statusCode = _.get(err, 'statusCode', '');
                const isGatewayTimeout = statusCode === 502 || statusCode === 504;
                const isConnectionReset = _.get(err, 'error.code', '') === 'ECONNRESET';

                if (maxRequestQueueLimitHit || isConnectionReset || isGatewayTimeout) {
                  // Tracking for logging purposes
                  if (isConnectionReset) numConnectionResets++;
                  if (maxRequestQueueLimitHit) numThrottled++;

                  lookupResults.push({
                    entity,
                    isVolatile: true,
                    data: {
                      summary: ['! Lookup limit reached'],
                      details: {
                        maxRequestQueueLimitHit,
                        isConnectionReset,
                        isGatewayTimeout,
                        summaryTag: '! Lookup limit reached',
                        errorMessage:
                          'The search failed due to the API search limit. You can retry your search by pressing the "Retry Search" button.'
                      }
                    }
                  });
                } else if (err) {
                  errors.push(parseErrorToReadableJSON(err));
                } else {
                  const body = fp.get('body', result);

                  if (
                    body === null ||
                    _isMiss(body) ||
                    _.isEmpty(body) ||
                    (body.response.results && _.isEmpty(body.response.results)) ||
                    (body.response.repositories && _.isEmpty(body.response.repositories))
                  ) {
                    lookupResults.push({
                      entity,
                      data: null
                    });
                  } else {
                    const formattedDetails = getFormattedDetails(body, options, entity);
                    lookupResults.push({
                      entity,
                      data: {
                        summary: getSummaryTags(formattedDetails),
                        details: formattedDetails
                      }
                    });
                  }
                }

                if (
                  lookupResults.length + errors.length + blockedEntities.length ===
                  entities.length
                ) {
                  if (numConnectionResets > 0 || numThrottled > 0) {
                    Logger.warn(
                      {
                        numEntitiesLookedUp: entities.length,
                        numConnectionResets: numConnectionResets,
                        numLookupsThrottled: numThrottled
                      },
                      'Lookup Limit Error'
                    );
                  }
                  // we got all our results
                  if (errors.length > 0) {
                    cb(errors);
                  } else {
                    Logger.trace({ LOOK: lookupResults });
                    cb(null, lookupResults);
                  }
                }
              }
            );
          } else {
            blockedEntities.push(entity);
          }
        });
        if (!hasValidIndicator) {
          cb(null, []);
        }
      } catch (error) {
        Logger.trace({ error: parseErrorToReadableJson(error) }, 'Error in doLookup');
      }
    });
  } catch (error) {
    Logger.trace({ error: parseErrorToReadableJson(error) }, 'Error in doLookup');
  }
}

const _fetchApiData = (entity, token, cookieJar, options, cb) => {
  // building request options...
  let requestOptions = {
    headers: {
      'X-SecurityCenter': token.token
    },
    jar: cookieJar,
    json: true
  };

  Logger.trace({ REQUEST_OPTIONS: requestOptions });
  if (entity.isIPv4) {
    (requestOptions.method = 'GET'),
      (requestOptions.uri = `${options.url}/rest/deviceInfo`),
      (requestOptions.qs = {
        ip: `${entity.value}`
      });
  } else if (entity.type === 'cve') {
    (requestOptions.method = 'POST'),
      (requestOptions.uri = `${options.url}/rest/analysis`),
      (requestOptions.body = {
        query: {
          type: 'vuln',
          tool: 'listvuln',
          startOffset: 0,
          endOffset: options.maxResults || 50,
          filters: [{ filterName: 'cveID', operator: '=', value: entity.value }],
          vulnTool: 'listvuln'
        },
        sourceType: 'cumulative',
        type: 'vuln'
      });
  } else {
    return;
  }
  // MAKE REQUESTS FOR ENTITY DATA...
  requestWithDefaults(requestOptions, function (error, res, body) {
    const statusCode = res && res.statusCode;

    if (error) {
      return cb(error);
    }

    Logger.trace(requestOptions);
    Logger.trace({ body, statusCode: statusCode || 'N/A' }, 'Result of Lookup');

    if (statusCodeIsInvalid(statusCode))
      cb({
        err: body,
        detail: `${body.error}: ${body.message}`
      });
    cb(null, {
      entity,
      body: statusCode === 200 ? body : null
    });
  });
};

const getSummaryTags = (formattedDetails) => {
  const tags = [];
  if (formattedDetails.response && formattedDetails.response.severityCritical) {
    tags.push(`Critical Severities: ${formattedDetails.response.severityCritical}`);
  }
  if (formattedDetails.response && formattedDetails.response.severityHigh) {
    tags.push(`High Severities: ${formattedDetails.response.severityHigh}`);
  }
  if (formattedDetails.response && formattedDetails.response.hasCompliance) {
    tags.push(`Has Compliance: ${formattedDetails.response.hasCompliance}`);
  }
  if (formattedDetails.response && !isNaN(formattedDetails.response.lastScan)) {
    tags.push(
      `Last Scan: ${DateTime.fromSeconds(
        formattedDetails.response.lastScan
      ).toLocaleString(DateTime.DATETIME_SHORT)}`
    );
  }
  if (formattedDetails.response && formattedDetails.response.totalRecords) {
    tags.push(`${formattedDetails.response.totalRecords} records found`);
    tags.push(
      `Critical Severities: ${formattedDetails.response.criticalSeverityResults.length}`
    );
  }
  return tags;
};

const _isMiss = (body) => !body || !body.response;

const getFormattedDetails = (body, options, entity) => ({
  ...body,
  ...(!entity.isIPv4 && {
    IpDetailsUrl:
      `${options.url}/#vulnerabilities/cumulative/sumip/` +
      `%7B%22filt%22%3A%20%5B%7B%22filterName%22%3A%20%22ip%22%2C%22value%22%3A%20%22${entity.value}%22%7D%5D%7D`
  }),
  response: {
    ...body.response,
    infoSeverityResults: getSeverityResults('0', body),
    lowSeverityResults: getSeverityResults('1', body),
    mediumSeverityResults: getSeverityResults('2', body),
    highSeverityResults: getSeverityResults('3', body),
    criticalSeverityResults: getSeverityResults('4', body)
  }
});

const getSeverityResults = (severityId, body) =>
  fp.filter(
    fp.flow(fp.get('severity.id'), fp.eq(severityId)),
    fp.get('response.results', body)
  );

function validateStringOption(errors, options, optionName, errMessage) {
  if (
    typeof options[optionName].value !== 'string' ||
    (typeof options[optionName].value === 'string' &&
      options[optionName].value.length === 0)
  ) {
    errors.push({
      key: optionName,
      message: errMessage
    });
  }
}

function validateOptions(options, callback) {
  let errors = [];

  validateStringOption(errors, options, 'url', 'You must provide a valid API URL');
  validateStringOption(errors, options, 'userName', 'You must provide a valid Username');
  validateStringOption(errors, options, 'password', 'You must provide a valid Password');

  if (options.maxConcurrent.value < 1) {
    errors = errors.concat({
      key: 'maxConcurrent',
      message: 'Max Concurrent Requests must be 1 or higher'
    });
  }

  if (options.minTime.value < 1) {
    errors = errors.concat({
      key: 'minTime',
      message: 'Minimum Time Between Lookups must be 1 or higher'
    });
  }

  callback(null, errors);
}

function _isInvalidEntity(entity) {
  if (entity.value.length > MAX_ENTITY_LENGTH) {
    return true;
  }

  if (entity.isIPv4 && IGNORED_IPS.has(entity.value)) {
    return true;
  }

  return false;
}

function _isEntityBlocklisted(entity, options) {
  const blocklist = options.blocklist;

  Logger.trace({ blocklist: blocklist }, 'checking to see what blocklist looks like');

  if (_.includes(blocklist, entity.value.toLowerCase())) {
    return true;
  }

  if (entity.isIP && !entity.isPrivateIP) {
    if (ipBlocklistRegex !== null) {
      if (ipBlocklistRegex.test(entity.value)) {
        Logger.debug({ ip: entity.value }, 'Blocked BlockListed IP Lookup');
        return true;
      }
    }
  }

  return false;
}

function onMessage(payload, options, callback) {
  switch (payload.action) {
    case 'retryLookup':
      doLookup([payload.entity], options, (err, lookupResults) => {
        if (err) {
          Logger.error({ err }, 'Error retrying lookup');
          callback(err);
        } else {
          callback(
            null,
            lookupResults && lookupResults[0] && lookupResults[0].data === null
              ? { data: { summary: ['No Results Found on Retry'] } }
              : lookupResults[0]
          );
        }
      });
      break;
  }
}

module.exports = {
  doLookup,
  onMessage,
  startup,
  validateOptions
};
