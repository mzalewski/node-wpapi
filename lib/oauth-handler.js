module.exports = function(verifyHandler) {

  var _oauthInstance = null;
  this.getOAuthInstance = function(authConfig, forceCreate) {
    if (_oauthInstance != null && ! forceCreate)
      return _oauthInstance;
      var oauth = require('oauth');
      return _oauthInstance = new oauth.OAuth(authConfig.requestUrl, authConfig.accessUrl, authConfig.clientId, authConfig.clientSecret, '1.0',null,'HMAC-SHA1' );

  };
  this.getRequestToken = function(oauth, requestObj, options, authConfig) {
    return new Promise( ( resolve, reject ) => {
        oauth.getOAuthRequestToken(function( err, token, secret, results ) {
            if ( err ) {
                return reject( err );
            }
            resolve({
                requestToken: token,
                secret: secret
            });
        });
    });
  };
  this.verifyAndFetchAccessToken = function(oauth) {

    return this.getRequestToken(oauth).then(function(requestToken) {
        return verifyHandler(`http://hotsource.io/oauth1/authorize?oauth_token=${requestToken.requestToken}&oauth_callback=oob`)
        .then(function(verifyCode) {
          return {
            requestToken: requestToken.requestToken,
            secret: requestToken.secret,
            verifier: verifyCode
          };
        });
    }).then(function(verifiedRequestToken) {

      return new Promise(function(resolve,reject) {

      oauth.getOAuthAccessToken(verifiedRequestToken.requestToken, verifiedRequestToken.secret, verifiedRequestToken.verifier, function( err, token, secret, results ) {
        if ( err ) {
           return reject( err );
       }
       return resolve({
           accessToken: token,
           accessTokenSecret: secret
       });
      })
    });
  });

  };
  this.signRequest = function(oauth,requestObj, options, accessToken) {
    var authHeader = oauth.authHeader(requestObj.getUrl(), accessToken.accessToken, accessToken.accessTokenSecret, requestObj.getMethod());
    requestObj.setHeader('Authorization', authHeader);
    return requestObj;
  };
  this.auth = function( requestObj, options ) {

      // Check options auth is an object and has oauth credentials
      if (typeof options.authCredentials !== "object" || !options.authCredentials.oauth)
        return Promise.resolve(false);
      var authConfig = options.authCredentials.oauth;

      if (!authConfig.accessToken && !authConfig.clientId)
        return Promise.resolve(false);

      var self = this;
      var oauth = this.getOAuthInstance(authConfig);
      var oauthPromise = null;
      if (authConfig.accessToken) {
          oauthPromise = Promise.resolve({accessToken: authConfig.accessToken, accessTokenSecret: authConfig.accessTokenSecret });
      } else {

        oauthPromise = this.verifyAndFetchAccessToken(oauth);
        // Cache the access token for future requests
        oauthPromise.then(function(accessTokenData) { authConfig.accessToken = accessTokenData.accessToken; authConfig.accessTokenSecret = accessTokenData.accessTokenSecret; });
      }

      return oauthPromise.then(function(accessTokenData) { return self.signRequest(oauth,requestObj, options, accessTokenData); });
  };
}
