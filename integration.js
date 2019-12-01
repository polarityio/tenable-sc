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

  if (
    typeof config.request.cert === "string" &&
    config.request.cert.length > 0
  ) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === "string" && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (
    typeof config.request.passphrase === "string" &&
    config.request.passphrase.length > 0
  ) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === "string" && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (
    typeof config.request.proxy === "string" &&
    config.request.proxy.length > 0
  ) {
    defaults.proxy = config.request.proxy;
  }

  if (typeof config.request.rejectUnauthorized === "boolean") {
    defaults.rejectUnauthorized = config.request.rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);
}

function getTokenCacheKey(options) {
  return options.apiKey + options.apiSecret;
}

function getAuthToken(options, callback) {
  let cacheKey = getTokenCacheKey(options);
  //let token = tokenCache.get(cacheKey);

  request(
    {
      method: "POST",
      uri: `${options.url}/rest/token`,
      body: {
        username: options.userName,
        password: options.password
      },
      json: true
    },
    (err, resp, body) => {
      if (err) {
        callback(err);
        return;
      }



      Logger.trace({ body: body }, "Result of token lookup");

      if (resp.statusCode != 200) {
        callback({ err: new Error("status code was not 200"), body: body });
        return;
      }

      let cookie = resp.headers['set-cookie'];

      if (typeof cookie[1] === undefined){
        callback({ err: new Error("Cookie Not Avilable"), body: body });
        return;
      }

      let theCookie = cookie[1];


      tokenCache.set(cacheKey, {cookie: theCookie, token: body.response.token});


      Logger.trace({ tokenCache: tokenCache}, "Checking TokenCache");

      callback(null, {cookie: theCookie, token: body.response.token});
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
      //callback({ err: err });
      return;
    }

    Logger.trace({ token: token }, "what does the token look like in doLookup");

    entities.forEach(entity => {
      //do the lookup

      if(entity.isIPv4){
      var cookieJar = request.jar();
      var cookie = token.cookie
      cookieJar.setCookie(token.cookie, options.url);

      let requestOptions = {
        method: "GET",
        uri: `${options.url}/rest/deviceInfo`,
        qs:{
            ip: entity.value
          },
        headers: {
          "X-SecurityCenter": token.token
        },
        jar: cookieJar,
        json: true
      };


      Logger.trace({ uri: requestOptions }, "Request URI");
      //Logger.trace({ uri: requestOptions.headers }, "Request Headers");
      //Logger.trace({ uri: requestOptions.qs }, "Request Query Parameters");

      tasks.push(function(done) {
        requestWithDefaults(requestOptions, function(error, res, body) {
          if (error) {
            return done(error);
          }

          Logger.trace(requestOptions);
          Logger.trace(
            { body: body, statusCode: res ? res.statusCode : "N/A" },
            "Result of Lookup"
          );

          let result = {};

          if (res.statusCode === 200) {
            // we got data!
            result = {
              entity: entity,
              body: body
            };
          } else if (res.statusCode === 404) {
            // no result found
            result = {
              entity: entity,
              body: null
            };
          } else if (res.statusCode === 202) {
            // no result found
            result = {
              entity: entity,
              body: null
            };
          } else {
            // unexpected status code
            return done({
              err: body,
              detail: `${body.error}: ${body.message}`
            });
          }

          done(null, result);
        });
      });
    } else if (entity.isDomain){
  var cookieJar = request.jar();
  var cookie = token.cookie
  cookieJar.setCookie(token.cookie, options.url);

  let requestOptions = {
    method: "GET",
    uri: `${options.url}/rest/deviceInfo`,
    qs:{
        dnsName: entity.value
      },
    headers: {
      "X-SecurityCenter": token.token
    },
    jar: cookieJar,
    json: true
  };


  Logger.trace({ uri: requestOptions }, "Request URI");
  //Logger.trace({ uri: requestOptions.headers }, "Request Headers");
  //Logger.trace({ uri: requestOptions.qs }, "Request Query Parameters");

  tasks.push(function(done) {
    requestWithDefaults(requestOptions, function(error, res, body) {
      if (error) {
        return done(error);
      }

      Logger.trace(requestOptions);
      Logger.trace(
        { body: body, statusCode: res ? res.statusCode : "N/A" },
        "Result of Lookup"
      );

      let result = {};

      if (res.statusCode === 200) {
        // we got data!
        result = {
          entity: entity,
          body: body
        };
      } else if (res.statusCode === 404) {
        // no result found
        result = {
          entity: entity,
          body: null
        };
      } else if (res.statusCode === 202) {
        // no result found
        result = {
          entity: entity,
          body: null
        };
      } else {
        // unexpected status code
        return done({
          err: body,
          detail: `${body.error}: ${body.message}`
        });
      }

      done(null, result);
    });
  });
}
});


    async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
      if (err) {
        Logger.error({ err: err }, "Error");
        cb(err);
        return;
      }

      results.forEach(result => {
        if (result.body === null || _isMiss(result.body) || _.isEmpty(result.body)) {
          lookupResults.push({
            entity: result.entity,
            data: null
          });
        } else {
          result.body.response.lastScan = new Date(parseInt(result.body.response.lastScan)*1000);
          result.body.response.lastAuthRun = new Date(parseInt(result.body.response.lastAuthRun)*1000);
          lookupResults.push({
            entity: result.entity,
            data: {
              summary: [],
              details: result.body
            }
          });
        }
      });

      Logger.debug({ lookupResults }, "Results");
      cb(null, lookupResults);
    });
  });
}

function _isMiss(body) {
  if (!body) {
    return true;
  }
}

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
    "apiKey",
    "You must provide a valid API Key"
  );
  validateStringOption(
    errors,
    options,
    "apiSecret",
    "You must provide a valid API Secret"
  );
  callback(null, errors);
}

module.exports = {
  doLookup: doLookup,
  startup: startup,
  validateOptions: validateOptions
};
