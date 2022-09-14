'use strict';

const request = require('postman-request');
const _ = require('lodash');
const fp = require('lodash/fp');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');

let Logger;
let requestWithDefaults;

const MAX_PARALLEL_LOOKUPS = 10;

const NodeCache = require('node-cache');
const tokenCache = new NodeCache({
  stdTTL: 1000 * 1000
});

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

  requestWithDefaults = request.defaults(defaults);
}

const getTokenCacheKey = (options) => options.apiKey + options.apiSecret;
const statusCodeIsInvalid = (statusCode) => [200, 404, 202].every((validStatusCode) => statusCode !== validStatusCode);

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

      Logger.trace({ body }, 'Result of token lookup');

      if (resp.statusCode != 200) {
        callback({ err: new Error('status code was not 200'), body });
        return;
      }

      let cookie = resp.headers['set-cookie'][1];

      if (typeof cookie === undefined) {
        callback({ err: new Error('Cookie Not Available'), body });
        return;
      }

      tokenCache.set(cacheKey, { cookie, token: body.response.token });

      Logger.trace({ tokenCache }, 'Checking TokenCache');

      callback(null, { cookie, token: body.response.token });
    }
  );
}

function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

  Logger.debug(entities);

  getAuthToken(options, (err, token) => {
    if (err) {
      Logger.error(err, 'Error getting auth token');
      cb({
        detail: err.detail ? err.detail : 'Unable to authenticate to Tenable',
        err
      });
      return;
    }

    Logger.trace({ token }, 'what does the token look like in doLookup');

    let { cookie } = token;

    entities.forEach((entity) => {
      let cookieJar = request.jar();
      cookieJar.setCookie(cookie, options.url);

      const requestOptions = {
        headers: {
          'X-SecurityCenter': token.token
        },
        jar: cookieJar,
        json: true
      };

      if (entity.isIPv4) {
        (requestOptions.method = 'GET'),
          (requestOptions.uri = `${options.url}/rest/deviceInfo`),
          (requestOptions.qs = {
            ip: `${entity.value}`
          });
      } else if (entity.isDomain) {
        (requestOptions.method = 'GET'),
          (requestOptions.uri = `${options.url}/rest/deviceInfo`),
          (requestOptions.qs = {
            dnsName: `${entity.value}`
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

      Logger.trace({ uri: requestOptions }, 'Request URI');

      tasks.push(function (done) {
        requestWithDefaults(requestOptions, function (error, res, body) {
          const statusCode = res && res.statusCode;
          if (error) {
            return done({
              detail: 'Network error',
              error
            });
          }

          Logger.trace(requestOptions);
          Logger.trace({ body, statusCode: statusCode || 'N/A' }, 'Result of Lookup');

          if (statusCodeIsInvalid(statusCode)) {
            return done({
              err: body,
              detail: `${body.error}: ${body.message}`
            });
          }

          done(null, {
            entity,
            body: statusCode === 200 ? body : null
          });
        });
      });
    });

    async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
      if (err) {
        Logger.error({ err }, 'Lookup Error');
        cb(err);
        return;
      }

      results.forEach(({ body, entity }) => {
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
          lookupResults.push({
            entity,
            data: {
              summary: [],
              details: getFormattedDetails(body, options, entity)
            }
          });
        }
      });

      Logger.debug({ lookupResults }, 'Results');
      cb(null, lookupResults);
    });
  });
}

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
    criticalSeverityResults: getSeverityResults('4', body),
    lastScan: new Date(parseInt(body.response.lastScan) * 1000),
    lastAuthRun: new Date(parseInt(body.response.lastAuthRun) * 1000)
  }
});

const getSeverityResults = (severityId, body) =>
  fp.filter(fp.flow(fp.get('severity.id'), fp.eq(severityId)), fp.get('response.results', body));

function validateStringOption(errors, options, optionName, errMessage) {
  if (
    typeof options[optionName].value !== 'string' ||
    (typeof options[optionName].value === 'string' && options[optionName].value.length === 0)
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
  callback(null, errors);
}

module.exports = {
  doLookup,
  startup,
  validateOptions
};
