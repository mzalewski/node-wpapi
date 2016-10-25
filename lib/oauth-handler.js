var OAuthHandler = function(callback) {
  this.callback = callback;
};

var tokenSecretCache = {};

OAuthHandler.prototype = {
  getOAuthInstance: function(authConfig, forceCreate) {

    if (this._oauthInstance  && ! forceCreate)
      return this._oauthInstance;
    var oauth = require('oauth');
    this.authConfig = authConfig;
    return this._oauthInstance = new oauth.OAuth(authConfig.requestUrl, authConfig.accessUrl, authConfig.clientId, authConfig.clientSecret, '1.0',null,'HMAC-SHA1' );

  },
  getRequestToken: function( requestObj, options ) {
    return new Promise( ( resolve, reject ) => {
        this.getOAuthInstance().getOAuthRequestToken(function( err, token, secret, results ) {
            if ( err ) {
                return reject( err );
            }
            resolve({
                requestToken: token,
                secret: secret
            });
        });
    });
  },
  getAuthorizeUrl: function(requestToken) {

    var callbackUrl = this.callback;
    if (typeof this.callback == "function")
      callbackUrl = "oob";

    return `http://hotsource.io/oauth1/authorize?oauth_token=${requestToken.requestToken}&oauth_callback=${callbackUrl}`;
  },
  authorizeRequestToken: function(tokenData, authorizeUrl) {

      return this.callback.call(this,authorizeUrl,this.authConfig);
  },
  verifyRequestToken: function(requestToken,verifier) {
    var self = this;

    return new Promise((resolve,reject) => {

      this.getOAuthInstance(this.authConfig).getOAuthAccessToken(requestToken.requestToken, requestToken.secret, verifier, function( err, token, secret, results ) {
        if ( err ) {

           return reject( err );
       }

       return resolve({
           accessToken: token,
           accessTokenSecret: secret
       });
      })
    }).then(function(accessTokenData) { self.authConfig.accessToken = accessTokenData.accessToken; self.authConfig.accessTokenSecret = accessTokenData.accessTokenSecret; return accessTokenData; });
  },
  signRequest: function( requestObj, options, accessToken) {
    var authHeader = this.getOAuthInstance(this.authConfig).authHeader(requestObj.getUrl(), accessToken.accessToken, accessToken.accessTokenSecret, requestObj.getMethod());
    requestObj.setHeader('Authorization', authHeader);
    return requestObj;
  },
  auth: function( requestObj, options ) {

    var extend = require( 'node.extend' );
    // Check options auth is an object and has oauth credentials
    if (typeof options.authCredentials !== "object" || !options.authCredentials.oauth)
      return Promise.resolve(false);
    this.authConfig = extend(this.authConfig||{},options.authCredentials.oauth);

    if (!this.authConfig.accessToken && !this.authConfig.clientId)
      return Promise.resolve(false);

    var self = this;
    var oauth = this.getOAuthInstance(self.authConfig);
    var oauthPromise = null;
    if (self.authConfig.accessToken) {
        oauthPromise = Promise.resolve({accessToken: self.authConfig.accessToken, accessTokenSecret: self.authConfig.accessTokenSecret });
    } else {

      oauthPromise = this.getRequestToken(oauth)
      .then(requestToken=>this.authorizeRequestToken(requestToken,this.getAuthorizeUrl(requestToken)).then(verifier=>this.verifyRequestToken(requestToken,verifier)))
      .catch(er=>console.log("Error",er));
      // Cache the access token for future requests

    }

    return oauthPromise.then(accessTokenData=>  this.signRequest(requestObj, options, accessTokenData) );

  }
};
module.exports = OAuthHandler;
