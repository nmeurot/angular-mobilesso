import { AuthConfigMobileSSO } from './base/auth.config-mobile-sso';
import { MobilessoStorageHelper } from './helper/mobilesso-storage-helper';
import { Injectable, NgZone, Optional } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { Observable, Subject, Subscription, of } from 'rxjs';
import { filter, delay, first } from 'rxjs/operators';
import {
    ValidationHandler,
    ValidationParams
} from './token-validation/validation-handler';
import {
    OAuthEvent,
    OAuthInfoEvent,
    OAuthErrorEvent,
    OAuthSuccessEvent
} from './model/events';
import {
    OAuthStorage,
    ParsedIdToken,
    OidcDiscoveryDoc,
    TokenResponse
} from './model/types';
import { b64DecodeUnicode } from './helper/base64-helper';

/**
 * Service for logging in and logging out with
 * OIDC and OAuth2. Supports implicit flow and
 * password flow.
 */
@Injectable()
export class MobileSsoService extends AuthConfigMobileSSO {
    // extending AuthConfig ist just for LEGACY reasons
    // to not break existing code

    /* The ValidationHandler used to validate received id_tokens*/
    public tokenValidationHandler: ValidationHandler;

     /*Informs about events, like token_received or token_expires. See the string enum EventType for a full list of events.*/
    private eventsSubject: Subject<OAuthEvent> = new Subject<OAuthEvent>();
    public events: Observable<OAuthEvent>;

    // Timers Subscriptions
    private accessTokenTimeoutSubscription: Subscription;
    private idTokenTimeoutSubscription: Subscription;



    /**
     * The received (passed around) state, when logging
     * in with implicit flow.
     */
    public state ?= '';

    // private silentRefreshPostMessageEventListener: EventListener;
    private grantTypesSupported: Array<string> = [];
    private sessionCheckEventListener: EventListener;
    private jwksUri: string;
    private sessionCheckTimer: any;
    private silentRefreshSubject: string;

    constructor(
        private ngZone: NgZone,
        private http: HttpClient,
        @Optional() storage: OAuthStorage,
        @Optional() tokenValidationHandler: ValidationHandler,
        @Optional() private config: AuthConfigMobileSSO,
        private storageHelper: MobilessoStorageHelper) {
            super();

            // Initialize List Events
            this.events = this.eventsSubject.asObservable();

            // initialize TokenValidationHandler if parameter is passed
            if (tokenValidationHandler) {
                this.tokenValidationHandler = tokenValidationHandler;
            }

            // Initialize the Authent Configuration if the parameter has been passed
            if (config) {
                this.configure(config);
            }

            // Define which will be the OAuthSotrage the storage on the local variable.
            // If a storage OAuthStorage is passed on parameter, it will be used as storage.
            // Else by default, it will be the "sessionStorage" of the browser which will be used
            try {
                if (storage) {
                    this.storageHelper.setStorage(storage);
                } else if (typeof sessionStorage !== 'undefined') {
                    this.storageHelper.setStorage(sessionStorage);
                }
            } catch (e) {
                console.error(
                    'cannot access sessionStorage. Consider setting an own storage implementation using setStorage',
                    e
                );
            }
            // If ha valid access token, and valide Id Token start timer to refresh the access token
            if (this.storageHelper.hasValidIdToken() && this.storageHelper.hasValidAccessToken()) {
                this.initExpirationTimers();
            }

            // Initialize default subscription events : when the event token received is raised, timers are activated
            this.setupRefreshTimer();

            // Define what to do when ''token_expires'' event is raised
            this.setupEventTokenExpires();
    }

    /* Use this method to configure the service
     * @param config the configuration
     */
    public configure(config: AuthConfigMobileSSO) {
        // For the sake of downward compatibility with
        // original configuration API
        Object.assign(this, new AuthConfigMobileSSO(), config);
        this.config = Object.assign({} as AuthConfigMobileSSO, new AuthConfigMobileSSO(), config);

        //
        if (this.sessionChecksEnabled) {
            this.setupSessionCheck();
        }
    }

    /**
     * To be called throught the mobileSsoService
     */
    public hasValidAccessToken() {
        return this.storageHelper.hasValidAccessToken();
    }

    /**
     * To be called throught the mobileSsoService
     */
    public getAccessToken() {
        return this.storageHelper.getAccessToken();
    }

    // ///////////////////////////////////////////
    // Events  Subscribe ///////////////////////////////////
    // /////////////////////////////////////////////////////////////

    /* Initialise the subcription on the event Token_reveived*/
    private setupRefreshTimer(): void {
        this.events.pipe(filter(e => e.type === 'token_received')).subscribe(_ => {
            this.initExpirationTimers();
        });
    }

    private setupSessionCheck() {
        this.events.pipe(filter(e => e.type === 'token_received')).subscribe(e => {
            this.initSessionCheck();
        });
    }

    private setupDiscoveryDocumentLoaded() {
        this.events.pipe(filter(e => e.type === 'discovery_document_loaded')).subscribe(e => {
            // TODO : To define !! doit lancer les Calls 1, 2 et 3 !! Avant c'etait : this.initAuthorizationCodeFlowInternal()
        });
    }

    /** Events done when the token_expires is raised.
     * For Access_toke, we retreive a new one
     * For Id token, we clean storages, to for authent
     */
    public setupEventTokenExpires() {
        this.events.pipe<OAuthInfoEvent>(filter<OAuthInfoEvent>(e => e.type === 'token_expires')).subscribe(e => {
            if (e.info !== null && e.info !== undefined) {
                // NEW Code : only  work on the refresh of accesstoken
                if (e.info === 'access_token') {
                    this.requestAccessToken_Call3()
                        .then(() => {
                            console.log('Success to refresh Acces Token');
                            this.initExpirationTimers();
                        })
                        .catch(error => {
                            console.error('Error in Automatically Refresh the Access Token: ');
                            console.error(error);
                        });
                } else if (e.info === 'id_token') {
                    // If it is the token id which expire, clear all storage (to for recall)
                    this.storageHelper.clearStorage();
                    this.clearAccessTokenTimer();
                    this.clearIdTokenTimer();
                }
            }
        });
    }


    // ///////////////////////////////////////////////////
    // Calls for Authorization code Mode
    // ///////////////////////////////////////////////////////

    // ------- Get docs (endpoints...etc..) , and  the Authorization Caode)

    /* Get docs (endpoints...etc..)
     * if the "issuer" is define on the config initialized on constructor, not need to define the fullWellKnowUrl */
    private loadDiscoveryDocumentAndRequestAuthorizationCode_Call1(fullWellKnownUrl: string = null): void {
        this.loadDiscoveryDocument(fullWellKnownUrl).then( () => {
            this.requestAuthorizationCode();
        });
    }

    /* Launch call to retreive Id Token, then call to retreive Access Token */
    public loadIdtokenAndAccessToken(): Promise<void>  {
        return new Promise( (resolve, rejectcall) => {
            this.requestIdToken_Call2().then(() => {
                this.requestAccessToken_Call3().then(() => {
                    resolve();
                }).catch( (reason) => {
                    rejectcall('Error retreiving Access Token : ' + reason);
                });
            }).catch( (reason) => {
                rejectcall('Error retreiving Id Token : ' + reason);
            });
        });

    }


    // -------- Call 1 : Get Authorization Code  ////////////////////////

    /* Use the Url Login retreive to call it and retreive the Authorization Code.
     * It is a Redirection */
    public requestAuthorizationCode(): void { // Old name : initAuthorizationCodeFlow()

        if (!this.validateUrlForHttps(this.loginUrl)) {
          throw new Error('loginUrl must use Http. Also check property requireHttps.');
        }

        this.createLoginUrl('', '', null, false, {}).then((url) => {
          // location.href = url;
          location.assign(url);
        })
          .catch(error => {
            console.error('Error in initAuthorizationCodeFlow');
            console.error(error);
          });
    }

    /* Create and call the login url (Mobile SSO) */
    private createLoginUrl(state = '', loginHint = '', customRedirectUri = '',  noPrompt = false, params: object = {}) {
        const that = this;
        let redirectUri: string;
        if (customRedirectUri) {
            redirectUri = customRedirectUri;
        } else {
            redirectUri = this.redirectUri;
        }

        let nonce = null;
        if (!this.disableNonceCheck) {
          nonce = this.storageHelper.createAndSaveNonce();
          if (state) {
            state = nonce + this.config.nonceStateSeparator + state;
          } else {
            state = nonce;
          }
        }

        if (!this.requestAccessToken) { // && !this.oidc) {
            throw new Error(
                'Either requestAccessToken or oidc or both must be true'
            );
        }

        this.responseType = 'code';
        const seperationChar = that.loginUrl.indexOf('?') > -1 ? '&' : '?';
        let scope = that.scope;

        if (!scope.match(/(^|\s)openid($|\s)/)) { // && this.oidc) {
            scope = 'openid ' + scope;
        }

        let url =
            that.loginUrl +
            seperationChar +
            'response_type=' +
            encodeURIComponent(that.responseType) +
            '&client_id=' +
            encodeURIComponent(that.clientId) +
            '&state=' +
            encodeURIComponent(state) +
            '&redirect_uri=' +
            encodeURIComponent(redirectUri) +
            '&scope=' +
            encodeURIComponent(scope);
        if (loginHint) {
            url += '&login_hint=' + encodeURIComponent(loginHint);
        }
        if (that.resource) {
            url += '&resource=' + encodeURIComponent(that.resource);
        }
        if (nonce) { // && this.oidc) {
            url += '&nonce=' + encodeURIComponent(nonce);
        }
        if (noPrompt) {
            url += '&prompt=none';
        }
        for (const key of Object.keys(params)) {
            url +=
                '&' + encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
        }
        if (this.customQueryParams) {
            for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                url +=
                    '&' + key + '=' + encodeURIComponent(this.customQueryParams[key]);
            }
        }
        return Promise.resolve(url);
    }

    // -------- Call 2 : Get Id Token ///////////////////////

    /* Retreive the Authorization Code from Urm and then request the Id Token */
    private requestIdToken_Call2(): Promise<object> {
        if (window.location.search && (window.location.search.startsWith('?code=') || window.location.search.includes('&code='))) {
            const parameter = window.location.search.split('?')[1].split('&');
            const codeParam = parameter.filter(param => param.includes('code='));
            const code = codeParam.length ? codeParam[0].split('code=')[1] : undefined;
            if (code) {
            return new Promise((resolve, rejectcall) => {
                this.getIdTokenFromAuthorizationCode(code).then(() => {
                    resolve();
                }).catch(err => {
                    rejectcall(err);
                });
            });
            } else {
                Promise.reject('No query parameter "code" on the request');
            }
        } else {
            return Promise.reject('No query parameter "code" on the request');
        }
    }

    /**
     * Get Id token using an intermediate code. Works for the Authorization Code flow.
     */
    private getIdTokenFromAuthorizationCode(code: string): Promise<object> {
        const params = new HttpParams()
            .set('grant_type', 'authorization_code')
            .set('code', code)
            .set('scope', 'openid email')
            .set('redirect_uri', this.redirectUri);
        return this.fetchIdToken(params);
    }

    // TODO : A decouper en 2 car la on recupere le Id Token et le Access Token
    private fetchIdToken(params: HttpParams): Promise<object> {

        if (!this.validateUrlForHttps(this.tokenEndpoint)) {
            throw new Error(
            'tokenEndpoint must use Http. Also check property requireHttps.'
            );
        }

        return new Promise((resolve, rejectcall) => {
            params = params.set('client_id', this.clientId);
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            const headers = new HttpHeaders().set(
                'Content-Type',
                'application/x-www-form-urlencoded'
            );

            this.http.post<TokenResponse>(this.tokenEndpoint, params, { headers }).subscribe(
                (tokenResponse) => {
                    this.debug('Id Token tokenResponse', tokenResponse);
                    if (tokenResponse.id_token) { // && this.oidc) {
                    this.processIdToken(tokenResponse.id_token, tokenResponse.access_token).
                        then(result => {
                            this.storageHelper.storeIdToken(result);
                            this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                            this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                            resolve(tokenResponse);
                        })
                        .catch(reason => {
                            this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
                            console.error('Error validating tokens');
                            console.error(reason);

                            rejectcall(reason);
                        });
                    } else {
                        this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                        this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                        resolve(tokenResponse);
                    }
                },
                (err) => {
                    console.error('Error getting token', err);
                    this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                    rejectcall(err);
                });
        });
    }


    public processIdToken(idToken: string, accessToken: string): Promise<ParsedIdToken> {
        const tokenParts = idToken.split('.');
        const headerBase64 = this.padBase64(tokenParts[0]);
        const headerJson = b64DecodeUnicode(headerBase64);
        const header = JSON.parse(headerJson);
        const claimsBase64 = this.padBase64(tokenParts[1]);
        const claimsJson = b64DecodeUnicode(claimsBase64);
        const claims = JSON.parse(claimsJson);
        const savedNonce = this.storageHelper.getNonce();

        if (Array.isArray(claims.aud)) {
            if (claims.aud.every(v => v !== this.clientId)) {
                const err = 'Wrong audience: ' + claims.aud.join(',');
                console.warn(err);
                return Promise.reject(err);
            }
        } else {
            if (claims.aud !== this.clientId) {
                const err = 'Wrong audience: ' + claims.aud;
                console.warn(err);
                return Promise.reject(err);
            }
        }

        /*
            if (this.getKeyCount() > 1 && !header.kid) {
                let err = 'There needs to be a kid property in the id_token header when multiple keys are defined via the property jwks';
                console.warn(err);
                return Promise.reject(err);
            }
            */

        if (!claims.sub) {
            const err = 'No sub claim in id_token';
            console.warn(err);
            return Promise.reject(err);
        }

        /* For now, we only check whether the sub against
             * silentRefreshSubject when sessionChecksEnabled is on
             * We will reconsider in a later version to do this
             * in every other case too.
             */
        if (
            this.sessionChecksEnabled &&
            this.silentRefreshSubject &&
            this.silentRefreshSubject !== claims['sub']
        ) {
            const err =
                'After refreshing, we got an id_token for another user (sub). ' +
                `Expected sub: ${this.silentRefreshSubject}, received sub: ${
                claims['sub']
                }`;

            console.warn(err);
            return Promise.reject(err);
        }

        if (!claims.iat) {
            const err = 'No iat claim in id_token';
            console.warn(err);
            return Promise.reject(err);
        }

        if (claims.iss !== this.issuer) {
            const err = 'Wrong issuer: ' + claims.iss;
            console.warn(err);
            return Promise.reject(err);
        }

        if (!this.disableNonceCheck && claims.nonce !== savedNonce) {
          const err = 'Wrong nonce: ' + claims.nonce;
          console.warn(err);
          return Promise.reject(err);
        }

        // TODO : Commented for the moment, because at_hash check...
        // if (
        //     !this.disableAtHashCheck &&
        //     this.requestAccessToken &&
        //     !claims['at_hash']
        // ) {
        //     const err = 'An at_hash is needed!';
        //     console.warn(err);
        //     return Promise.reject(err);
        // }

        const now = Date.now();
        const issuedAtMSec = claims.iat * 1000;
        const expiresAtMSec = claims.exp * 1000;
        const tenMinutesInMsec = 1000 * 60 * 10;

        if (
            issuedAtMSec - tenMinutesInMsec >= now ||
            expiresAtMSec + tenMinutesInMsec <= now
        ) {
            const err = 'Token has been expired';
            console.error(err);
            console.error({
                now: now,
                issuedAtMSec: issuedAtMSec,
                expiresAtMSec: expiresAtMSec
            });
            return Promise.reject(err);
        }

        const validationParams: ValidationParams = {
            accessToken: accessToken,
            idToken: idToken,
            jwks: this.jwks,
            idTokenClaims: claims,
            idTokenHeader: header,
            loadKeys: () => this.loadJwks()
        };

        // TODO : Commented for the moment, because at_hash check...
        // if (
        //     !this.disableAtHashCheck &&
        //     this.requestAccessToken &&
        //     !this.checkAtHash(validationParams)
        // ) {
        //     const err = 'Wrong at_hash';
        //     console.warn(err);
        //     return Promise.reject(err);
        // }
//
        return this.checkSignature(validationParams).then(_ => {
            const result: ParsedIdToken = {
                idToken: idToken,
                idTokenClaims: claims,
                idTokenClaimsJson: claimsJson,
                idTokenHeader: header,
                idTokenHeaderJson: headerJson,
                idTokenExpiresAt: expiresAtMSec
            };
            return result;
        });
    }

    // -------- Call 3 : Get Access Token /////////////////////

    /* Retreive the Authorization Code and thant request the Id Token */
    private requestAccessToken_Call3(): Promise<void> {
        // Check the call2Response and retreive idToken
        const idToken = this.storageHelper.getIdToken();
        if (idToken) {
            return new Promise((resolve, rejectcall) => {
                this.getAccessTokenFromIdToken(idToken).then(result => {
                    resolve();
                }).catch(err => {
                    rejectcall(err);
                });
            });
            } else {
                return Promise.resolve();
            }

    }

    /**
     * Get Id token using an intermediate code. Works for the Authorization Code flow.
     */
    private getAccessTokenFromIdToken(idToken: string): Promise<object> {
        const params = new HttpParams()
            .set('grant_type', 'urn:ietf:params:oauth:grant-type:jwt-bearer')
            .set('assertion', idToken);
        return this.fetchAccessToken(params);
    }

    private fetchAccessToken(params: HttpParams): Promise<object> {
        if (!this.validateUrlForHttps(this.tokenEndpoint)) {
            throw new Error(
            'tokenEndpoint must use Http. Also check property requireHttps.'
            );
        }

        return new Promise((resolve, rejectcall) => {
            params = params.set('client_id', this.clientId);
            params = params.set('scope', this.scope);

            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            const headers = new HttpHeaders().set(
                'Content-Type',
                'application/x-www-form-urlencoded'
            );

            this.http.post<TokenResponse>(this.tokenEndpoint, params, { headers }).subscribe(
            (tokenResponse) => {
                this.debug('Accesst token Response : ', tokenResponse);
                this.storeAccessTokenResponse(
                    tokenResponse.access_token,
                    tokenResponse.refresh_token,
                    tokenResponse.expires_in,
                    tokenResponse.scope);

                this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                resolve(tokenResponse);
            },
            (err) => {
                console.error('Error getting token', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                rejectcall(err);
            }
            );
        });
    }

    /* Store the Access Token, and associated data */
    private storeAccessTokenResponse(
        accessToken: string,
        refreshToken: string,
        expiresIn: number, grantedScopes: String
    ): void {
        this.storageHelper.storeAccessToken(accessToken);
        if (grantedScopes) {
            this.storageHelper.storeGrantedScopes(JSON.stringify(grantedScopes.split('+')));
        }
        this.storageHelper.storeAccessTokenStoredAt(Date.now().toString());
        if (expiresIn) {
            const expiresInMilliSeconds = expiresIn * 1000;
            const now = new Date();
            const expiresAt = now.getTime() + expiresInMilliSeconds;
            this.storageHelper.storeAccessTokenExpiresAt(expiresAt.toString());
        }
        if (refreshToken) {
            this.storageHelper.storeRefreshToken(refreshToken);
        }
    }

    // -------- Common /////////////////////////////////
    private checkAtHash(params: ValidationParams): boolean {
        if (!this.tokenValidationHandler) {
            console.warn(
                'No tokenValidationHandler configured. Cannot check at_hash.'
            );
            return true;
        }
        return this.tokenValidationHandler.validateAtHash(params);
    }

    private checkSignature(params: ValidationParams): Promise<any> {
        if (!this.tokenValidationHandler) {
            console.warn(
                'No tokenValidationHandler configured. Cannot check signature.'
            );
            return Promise.resolve(null);
        }
        return this.tokenValidationHandler.validateSignature(params);
    }

    private padBase64(base64data): string {
        while (base64data.length % 4 !== 0) {
            base64data += '=';
        }
        return base64data;
    }

    // -------- Call Jwks : Get the Discovery Document  /////////////////////

    /* (from .well-known/openid-configuration url) */
    /**
     * Loads the discovery document to configure most
     * properties of this service. The url of the discovery
     * document is infered from the issuer's url according
     * to the OpenId Connect spec. To use another url you
     * can pass it to to optional parameter fullUrl.
     *
     * @param fullUrl
     */
    public loadDiscoveryDocument(fullUrl: string = null): Promise<object> {
        return new Promise((resolve, rejectcall) => {
            if (!fullUrl) {
                fullUrl = this.issuer || '';
                if (!fullUrl.endsWith('/')) {
                    fullUrl += '/';
                }
                fullUrl += '.well-known/openid-configuration';
            }

            if (!this.validateUrlForHttps(fullUrl)) {
                rejectcall('issuer must use Https. Also check property requireHttps.');
                return;
            }

            this.http.get<OidcDiscoveryDoc>(fullUrl).subscribe(
                doc => {
                    if (!this.validateDiscoveryDocument(doc)) {
                        this.eventsSubject.next(
                            new OAuthErrorEvent('discovery_document_validation_error', null)
                        );
                        rejectcall('discovery_document_validation_error');
                        return;
                    }

                    this.loginUrl = doc.authorization_endpoint;
                    this.logoutUrl = doc.end_session_endpoint || this.logoutUrl;
                    this.grantTypesSupported = doc.grant_types_supported;
                    this.issuer = doc.issuer;
                    this.tokenEndpoint = doc.token_endpoint;
                    this.userinfoEndpoint = doc.userinfo_endpoint;
                    this.jwksUri = doc.jwks_uri;
                    this.sessionCheckIFrameUrl = doc.check_session_iframe || this.sessionCheckIFrameUrl;

                    if (this.sessionChecksEnabled) {
                        this.restartSessionChecksIfStillLoggedIn();
                    }

                    this.loadJwks()
                        .then(jwks => {
                            const result: object = {
                                discoveryDocument: doc,
                                jwks: jwks
                            };

                            const event = new OAuthSuccessEvent(
                                'discovery_document_loaded',
                                result
                            );
                            this.eventsSubject.next(event);
                            resolve(event);
                            return;
                        })
                        .catch(err => {
                            this.eventsSubject.next(
                                new OAuthErrorEvent('discovery_document_load_error', err)
                            );
                            rejectcall(err);
                            return;
                        });
                },
                err => {
                    console.error('error loading discovery document', err);
                    this.eventsSubject.next(
                        new OAuthErrorEvent('discovery_document_load_error', err)
                    );
                    rejectcall(err);
                }
            );
        });
    }

    /* Load JWKS uri */
    private loadJwks(): Promise<object> {
        return new Promise<object>((resolve, rejectcall) => {
            if (this.jwksUri) {
                this.http.get(this.jwksUri).subscribe(
                    jwks => {
                        this.jwks = jwks;
                        this.eventsSubject.next(
                            new OAuthSuccessEvent('discovery_document_loaded')
                        );
                        resolve(jwks);
                    },
                    err => {
                        console.error('error loading jwks', err);
                        this.eventsSubject.next(
                            new OAuthErrorEvent('jwks_load_error', err)
                        );
                        rejectcall(err);
                    }
                );
            } else {
                resolve(null);
            }
        });
    }

    private validateDiscoveryDocument(doc: OidcDiscoveryDoc): boolean {
        let errors: string[];

        if (!this.skipIssuerCheck && doc.issuer !== this.issuer) {
            console.error(
                'invalid issuer in discovery document',
                'expected: ' + this.issuer,
                'current: ' + doc.issuer
            );
            return false;
        }

        errors = this.validateUrlFromDiscoveryDocument(doc.authorization_endpoint);
        if (errors.length > 0) {
            console.error(
                'error validating authorization_endpoint in discovery document',
                errors
            );
            return false;
        }

        errors = this.validateUrlFromDiscoveryDocument(doc.end_session_endpoint);
        if (errors.length > 0) {
            console.error(
                'error validating end_session_endpoint in discovery document',
                errors
            );
            return false;
        }

        errors = this.validateUrlFromDiscoveryDocument(doc.token_endpoint);
        if (errors.length > 0) {
            console.error(
                'error validating token_endpoint in discovery document',
                errors
            );
        }

        errors = this.validateUrlFromDiscoveryDocument(doc.userinfo_endpoint);
        if (errors.length > 0) {
            console.error(
                'error validating userinfo_endpoint in discovery document',
                errors
            );
            return false;
        }

        errors = this.validateUrlFromDiscoveryDocument(doc.jwks_uri);
        if (errors.length > 0) {
            console.error('error validating jwks_uri in discovery document', errors);
            return false;
        }

        if (this.sessionChecksEnabled && !doc.check_session_iframe) {
            console.warn(
                'sessionChecksEnabled is activated but discovery document' +
                ' does not contain a check_session_iframe field'
            );
        }

        // this.sessionChecksEnabled = !!doc.check_session_iframe;

        return true;
    }



    // ///////////////////////////////////////////
    // Divers  ///////////////////////////////////
    // /////////////////////////////////////////////////////////////

    /* */
    private validateUrlFromDiscoveryDocument(url: string): string[] {
        const errors: string[] = [];
        const httpsCheck = this.validateUrlForHttps(url);
        const issuerCheck = this.validateUrlAgainstIssuer(url);

        if (!httpsCheck) {
            errors.push(
                'https for all urls required. Also for urls received by discovery.'
            );
        }

        if (!issuerCheck) {
            errors.push(
                'Every url in discovery document has to start with the issuer url.' +
                'Also see property strictDiscoveryDocumentValidation.'
            );
        }

        return errors;
    }

    private validateUrlAgainstIssuer(url: string) {
        if (!this.strictDiscoveryDocumentValidation) {
            return true;
        }
        if (!url) {
            return true;
        }
        return url.toLowerCase().startsWith(this.issuer.toLowerCase());
    }

    /* Validate that the url is on https */
    private validateUrlForHttps(url: string): boolean {
        if (!url) {
            return true;
        }

        const lcUrl = url.toLowerCase();

        if (this.requireHttps === false) {
            return true;
        }

        if (
            (lcUrl.match(/^http:\/\/localhost($|[:\/])/) ||
                lcUrl.match(/^http:\/\/localhost($|[:\/])/)) &&
            this.requireHttps === 'remoteOnly'
        ) {
            return true;
        }

        return lcUrl.startsWith('https://');
    }

    /* Debug method on console*/
    private debug(...args): void {
        if (this.showDebugInformation) {
            console.log(args);
        }
    }

    // ///////////////////////////////////////////
    // Timers ///////////////////////////////////
    // /////////////////////////////////////////////////////////////

    /*  Initialize the timers for the Expiration of the id token and the access token*/
    private initExpirationTimers(): void {
        this.clearAccessTokenTimer();
        this.clearIdTokenTimer();
        this.setupExpirationTimers();
    }

    /* Setup the Expiration timers for the Id Token and the Access Token*/
    private setupExpirationTimers(): void {
        const idTokenExp = this.storageHelper.getIdTokenExpiration() || Number.MAX_VALUE;
        const accessTokenExp = this.storageHelper.getAccessTokenExpiration() || Number.MAX_VALUE;
        const useAccessTokenExp = accessTokenExp <= idTokenExp;

        if (this.storageHelper.hasValidAccessToken() && useAccessTokenExp) {
            this.setupAccessTokenTimer();
        }

        if (this.storageHelper.hasValidIdToken() && !useAccessTokenExp) {
            this.setupIdTokenTimer();
        }
    }

    private setupAccessTokenTimer(): void {
        if (this.autoRefreshAccessToken) {
            const expiration = this.storageHelper.getAccessTokenExpiration();
            const storedAt = this.storageHelper.getAccessTokenStoredAt();
            const timeout = this.calcTimeout(storedAt, expiration);

            this.ngZone.runOutsideAngular(() => {
                this.accessTokenTimeoutSubscription = of(
                    new OAuthInfoEvent('token_expires', 'access_token')
                )
                    .pipe(delay(timeout))
                    .subscribe(e => {
                        this.ngZone.run(() => {
                            this.eventsSubject.next(e);
                        });
                    });
            });
        }
    }

    private setupIdTokenTimer(): void {
        const expiration = this.storageHelper.getIdTokenExpiration();
        const storedAt = this.storageHelper.getIdTokenStoredAt();
        const timeout = this.calcTimeout(storedAt, expiration);

        this.ngZone.runOutsideAngular(() => {
            this.idTokenTimeoutSubscription = of(
                new OAuthInfoEvent('token_expires', 'id_token'))
                .pipe(delay(timeout))
                .subscribe(e => {
                    this.ngZone.run(() => {
                        this.eventsSubject.next(e);
                    });
                });
        });
    }

    private clearAccessTokenTimer(): void {
        if (this.accessTokenTimeoutSubscription) {
            this.accessTokenTimeoutSubscription.unsubscribe();
        }
    }

    private clearIdTokenTimer(): void {
        if (this.idTokenTimeoutSubscription) {
            this.idTokenTimeoutSubscription.unsubscribe();
        }
    }

    private calcTimeout(storedAt: number, expiration: number): number {
        const delta = (expiration - storedAt) * this.timeoutFactor;
        return delta;
    }


    // ///////////////////////////////////////////
    // Session Management : Session Check will be only used when the SessionCheck is enable ///////////////////////////////////
    // /////////////////////////////////////////////////////////////

    private initSessionCheck(): void {
        if (!this.canPerformSessionCheck()) {
            return;
        }

        const existingIframe = document.getElementById(this.sessionCheckIFrameName);
        if (existingIframe) {
            document.body.removeChild(existingIframe);
        }

        const iframe = document.createElement('iframe');
        iframe.id = this.sessionCheckIFrameName;

        this.setupSessionCheckEventListener();

        const url = this.sessionCheckIFrameUrl;
        iframe.setAttribute('src', url);
        // iframe.style.visibility = 'hidden';
        iframe.style.display = 'none';
        document.body.appendChild(iframe);

        this.startSessionCheckTimer();
    }

    /* Check if the Session Check can be done */
    private canPerformSessionCheck(): boolean {
        if (!this.sessionChecksEnabled) {
            return false;
        }
        if (!this.sessionCheckIFrameUrl) {
            console.warn(
                'sessionChecksEnabled is activated but there ' +
                'is no sessionCheckIFrameUrl'
            );
            return false;
        }
        const sessionState = this.storageHelper.getSessionState();
        if (!sessionState) {
            console.warn(
                'sessionChecksEnabled is activated but there ' + 'is no session_state'
            );
            return false;
        }
        if (typeof document === 'undefined') {
            return false;
        }

        return true;
    }

    public restartSessionChecksIfStillLoggedIn(): void {
        if (this.storageHelper.hasValidIdToken()) {
            this.initSessionCheck();
        }
    }

    private setupSessionCheckEventListener(): void {
        this.removeSessionCheckEventListener();

        this.sessionCheckEventListener = (e: MessageEvent) => {
            const origin = e.origin.toLowerCase();
            const issuer = this.issuer.toLowerCase();

            this.debug('sessionCheckEventListener');

            if (!issuer.startsWith(origin)) {
                this.debug(
                    'sessionCheckEventListener',
                    'wrong origin',
                    origin,
                    'expected',
                    issuer
                );
            }

            switch (e.data) {
                case 'unchanged':
                    this.handleSessionUnchanged();
                    break;
                case 'changed':
                    this.handleSessionChange();
                    break;
                case 'error':
                    this.handleSessionError();
                    break;
            }

            this.debug('got info from session check inframe', e);
        };

        window.addEventListener('message', this.sessionCheckEventListener);
    }

    private handleSessionError(): void {
        this.stopSessionCheckTimer();
        this.eventsSubject.next(new OAuthInfoEvent('session_error'));
    }

    private handleSessionUnchanged(): void {
        this.debug('session check', 'session unchanged');
    }

    private handleSessionChange(): void {
        /* events: session_changed, relogin, stopTimer, logged_out*/
        this.eventsSubject.next(new OAuthInfoEvent('session_changed'));
        this.stopSessionCheckTimer();
        if (this.silentRefreshRedirectUri) {
            /* TODO : it has been DELETED
                Need to rework first the method silentRefresh(params) !!!!!!!!!!!!!!!

                this.silentRefresh().catch(_ =>
                    this.debug('silent refresh failed after session changed')
                );
                this.waitForSilentRefreshAfterSessionChange();
            */
        } else {
            this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
            this.logOut(true);
        }
    }

    private waitForSilentRefreshAfterSessionChange() {
        this.events
            .pipe(
                filter(
                    (e: OAuthEvent) =>
                        e.type === 'silently_refreshed' ||
                        e.type === 'silent_refresh_timeout' ||
                        e.type === 'silent_refresh_error'
                ),
                first()
            )
            .subscribe(e => {
                if (e.type !== 'silently_refreshed') {
                    this.debug('silent refresh did not work after session changed');
                    this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
                    this.logOut(true);
                }
            });
    }

    private removeSessionCheckEventListener(): void {
        if (this.sessionCheckEventListener) {
            window.removeEventListener('message', this.sessionCheckEventListener);
            this.sessionCheckEventListener = null;
        }
    }

    private startSessionCheckTimer(): void {
        this.stopSessionCheckTimer();
        this.sessionCheckTimer = setInterval(
            this.checkSession.bind(this),
            this.sessionCheckIntervall
        );
    }

    private stopSessionCheckTimer(): void {
        if (this.sessionCheckTimer) {
            clearInterval(this.sessionCheckTimer);
            this.sessionCheckTimer = null;
        }
    }

    private checkSession(): void {
        const iframe: any = document.getElementById(this.sessionCheckIFrameName);

        if (!iframe) {
            console.warn(
                'checkSession did not find iframe',
                this.sessionCheckIFrameName
            );
        }

        const sessionState = this.storageHelper.getSessionState();

        if (!sessionState) {
            this.stopSessionCheckTimer();
        }

        const message = this.clientId + ' ' + sessionState;
        iframe.contentWindow.postMessage(message, this.issuer);
    }

    /**
     * Removes all tokens and logs the user out.
     * If a logout url is configured, the user is
     * redirected to it.
     * @param noRedirectToLogoutUrl
     */
    public logOut(noRedirectToLogoutUrl = false): void {
        const id_token = this.storageHelper.getIdToken();
        this.storageHelper.clearStorage();

        this.silentRefreshSubject = null;

        this.eventsSubject.next(new OAuthInfoEvent('logout'));

        if (!this.logoutUrl) {
            return;
        }
        if (noRedirectToLogoutUrl) {
            return;
        }
        if (!id_token) {
            return;
        }

        let logoutUrl: string;

        if (!this.validateUrlForHttps(this.logoutUrl)) {
            throw new Error(
                'logoutUrl must use Http. Also check property requireHttps.'
            );
        }

        // For backward compatibility
        if (this.logoutUrl.indexOf('{{') > -1) {
            logoutUrl = this.logoutUrl
                .replace(/\{\{id_token\}\}/, id_token)
                .replace(/\{\{client_id\}\}/, this.clientId);
        } else {
            logoutUrl =
                this.logoutUrl +
                (this.logoutUrl.indexOf('?') > -1 ? '&' : '?') +
                'id_token_hint=' +
                encodeURIComponent(id_token) +
                '&post_logout_redirect_uri=' +
                encodeURIComponent(this.postLogoutRedirectUri || this.redirectUri);
        }
        location.href = logoutUrl;
    }
}
