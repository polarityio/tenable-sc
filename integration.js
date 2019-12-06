"use strict";

const request = require("request");
const _ = require("lodash");
const config = require("./config/config");
const async = require("async");
const fs = require("fs");

let Logger;
let requestWithDefaults;

const MAX_PARALLEL_LOOKUPS = 10;

const NodeCache = require("node-cache");
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

  if (typeof cert === "string" && cert.length > 0) {
    defaults.cert = fs.readFileSync(cert);
  }

  if (typeof key === "string" && key.length > 0) {
    defaults.key = fs.readFileSync(key);
  }

  if (typeof ca === "string" && ca.length > 0) {
    defaults.ca = fs.readFileSync(ca);
  }

  if (typeof passphrase === "string" && passphrase.length > 0) {
    defaults.passphrase = passphrase;
  }

  if (typeof proxy === "string" && proxy.length > 0) {
    defaults.proxy = proxy;
  }

  if (typeof rejectUnauthorized === "boolean") {
    defaults.rejectUnauthorized = rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);
}

const getTokenCacheKey = (options) => options.apiKey + options.apiSecret;
const statusCodeIsInvalid = (statusCode) => [200, 404, 202].every((validStatusCode) => statusCode !== validStatusCode);

function getAuthToken({ url: tenableScUrl, userName, password, ...options }, callback) {
  let cacheKey = getTokenCacheKey(options);

  request(
    {
      method: "POST",
      uri: `${tenableScUrl}/rest/token`,
      body: {
        username: userName,
        password
      },
      json: true
    }, (err, resp, body) => {
      if (err) {
        callback(err);
        return;
      }

      Logger.trace({ body }, "Result of token lookup");

      if (resp.statusCode != 200) {
        callback({ err: new Error("status code was not 200"), body });
        return;
      }

      let cookie = resp.headers['set-cookie'][1];

      if (typeof cookie === undefined) {
        callback({ err: new Error("Cookie Not Avilable"), body });
        return;
      }

      tokenCache.set(cacheKey, { cookie, token: body.response.token });

      Logger.trace({ tokenCache }, "Checking TokenCache");

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
      Logger.error("get token errored", err);
      return;
    }

    Logger.trace({ token }, "what does the token look like in doLookup");

    let { cookie } = token;
    const tenableScUrl = options.url;
    
    entities.forEach(entity => {
      const qsKey = entity.isIPv4 ? "ip" : entity.isDomain && "dnsName";
      if (!qsKey)
        return done({
          message: "You have added a new Type that will not work with this Integration"
        });

      let cookieJar = request.jar();
      cookieJar.setCookie(cookie, tenableScUrl);

      const requestOptions = {
        method: "GET",
        uri: `${tenableScUrl}/rest/deviceInfo`,
        qs: {
          [qsKey]: entity.value
        },
        headers: {
          "X-SecurityCenter": token.token
        },
        jar: cookieJar,
        json: true
      };


      Logger.trace({ uri: requestOptions }, "Request URI");

      tasks.push(function (done) {
        requestWithDefaults(requestOptions, function (error, res, body) {
          const statusCode = res && res.statusCode;
          if (error) {
            return done(error);
          }

          Logger.trace(requestOptions);
          Logger.trace(
            { body, statusCode: statusCode || "N/A" },
            "Result of Lookup"
          );

          if (statusCodeIsInvalid(statusCode))
            return done({
              err: body,
              detail: `${body.error}: ${body.message}`
            });

          done(null, {
            entity,
            body: statusCode === 200 ? body : null
          });
        });
      });
    });


    async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
      if (err) {
        Logger.error({ err }, "Error");
        cb(err);
        return;
      }

      results.forEach(({ body, entity }) => {
        if (body === null || _isMiss(body) || _.isEmpty(body)) {
          lookupResults.push({
            entity,
            data: null
          });
        } else {
          body.response.lastScan = new Date(parseInt(body.response.lastScan) * 1000);
          body.response.lastAuthRun = new Date(parseInt(body.response.lastAuthRun) * 1000);
          const details = !entity.isIPv4 ? body : {
            ...body,
            IpDetailsUrl: `${tenableScUrl}/#vulnerabilities/cumulative/sumip/` +
              `%7B%22filt%22%3A%20%5B%7B%22filterName%22%3A%20%22ip%22%2C%22value%22%3A%20%22${entity.value}%22%7D%5D%7D`
          };
          
          lookupResults.push({
            entity,
            data: {
              summary: [],
              details
            }
          });
        }
      });

      Logger.debug({ lookupResults }, "Results");
      cb(null, lookupResults);
    });
  });
}

const _isMiss = (body) => !body || !body.response || !body.response.score;

function validateStringOption(errors, options, optionName, errMessage) {
  if (
    typeof options[optionName].value !== "string" ||
    (typeof options[optionName].value === "string" &&
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

  validateStringOption(
    errors,
    options,
    "url",
    "You must provide a valid API URL"
  );
  validateStringOption(
    errors,
    options,
    "userName",
    "You must provide a valid Username"
  );
  validateStringOption(
    errors,
    options,
    "password",
    "You must provide a valid Password"
  );
  callback(null, errors);
}

module.exports = {
  doLookup,
  startup,
  validateOptions
};
