import { HttpClient } from '@angular/common/http';
import { AuthConfigMobileSSO } from './base/auth.config-mobile-sso';
import { JwksValidationHandler } from './token-validation/jwks-validation-handler';
import { Injectable, Optional } from '@angular/core';
import { TokenResponse } from './model/types';
import { map, catchError } from 'rxjs/operators';
import { MobileSsoService } from './mobile-sso-service';

@Injectable()
export class MobileSsoHelper {

    /**
     * Main constructor
     */
    constructor(private httpClient: HttpClient, private mobileSSoService: MobileSsoService) {
    }

    /**
     * Authentication with OIDC for MobileSSO (Mode "Authorization Code")
     * @param config AuthConfigMobileSSO parameters
     * @param loginServiceUrl Url to our own service login to validate the Access Token retreived and validate login
     *              (and / or generate internal JWT application token)
     * @param showLogInfo Define if we display logs INFO or not
     * @param callback  is an object with at least the method what to do more when Access Token is received. It is optionnal :
     *          applyToken(data: TokenResponse): void;
     */
    public authenticate(config: AuthConfigMobileSSO,
                        loginServiceUrl: string,
                        showLogInfo = false,
                        @Optional() callback: any): void {
        // Configaure with the custom AuthConfigMobileSSO config
        this.mobileSSoService.configure(config);
        // Init the handler for the JWKS validation
        this.mobileSSoService.tokenValidationHandler = new JwksValidationHandler();
        // Retreive the .well-known/openid-configuration to retreive endpoints
        this.mobileSSoService.loadDiscoveryDocument().then(() => {
            // Launch specific process OIDC for MobileSSO, and retreive IdToken and Access Token from MobileSSO
            this.mobileSSoService.loadIdtokenAndAccessToken().then(() => {
                if (this.mobileSSoService.hasValidAccessToken()) {
                    // Process to JWT token handling : Call internal URL login of our application with AccessToken as parameter.
                    // This Login Service will validate the Access Token passed and return the Internal JWT Application Token
                    this.LogInfo('AccessToken valid !', showLogInfo);
                    this.httpClient.post<TokenResponse>(loginServiceUrl, { access_token: this.mobileSSoService.getAccessToken() })
                    .pipe(map(data => {
                        // the Internal JWT Application Token has been retreive from the login service of the application
                        this.LogInfo('Internal JWT Application Token received', showLogInfo);
                        // Method on WebApp to store/apply the Internal JWT Application Token on storage, to reuse it after
                        if (callback) {
                            callback.applyToken(data);
                        }
                    }), catchError(err => {
                        this.LogError('Error on getting Internal JWT Application Token');
                        return err;
                    })).subscribe();
                    return true;
                } else {
                    this.LogWarning('AccessToken INVALID! Relaunch requestAuthorizationCode() and retry login (redirect to MobileSSO)');
                    this.mobileSSoService.requestAuthorizationCode();
                    return false;
                }
            }).catch( err => {
                this.LogError('Error loading Idtoken And AccessToken : ' + err);
                this.LogError('Retry get Authorization code');
                this.mobileSSoService.requestAuthorizationCode();
                return false;
            });
        }).catch( err => {
            this.LogError('Error on oidc authentication initialization : ' + err);
            return false;
        });
    }

    /**
     * @param data displaye console log INFO
     */
    private LogInfo(data: string, showLogInfo: boolean) {
        if (showLogInfo) {
            console.log(data);
        }
    }

    /**
     * @param data displaye console log ERROR
     */
    private LogError(data: string) {
        console.error(data);
    }

    /**
     * @param data displaye console log WARN
     */
    private LogWarning(data: string) {
        console.warn(data);
    }
}
