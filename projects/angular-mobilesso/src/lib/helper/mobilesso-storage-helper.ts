import { ParsedIdToken } from '../model/types';
import { Injectable } from '@angular/core';
import { OAuthStorage } from '../model/types';

@Injectable()
export class MobilessoStorageHelper {

    // Local OAuthStorage binded to the sessionStorage by default
    private _storage: OAuthStorage;


    // ------- Common ////////////////////////////////////

    /**
     * INITIALIZE / Sets a custom storage used to store the received
     * tokens on client side. By default, the browser's
     * sessionStorage is used.
     * @param storage
     */
    public setStorage(storage: OAuthStorage): void {
        this._storage = storage;
    }

    public clearStorage() {
        this._storage.removeItem('access_token');
        this._storage.removeItem('id_token');
        this._storage.removeItem('refresh_token');
        this._storage.removeItem('nonce');
        this._storage.removeItem('access_token_expires_at');
        this._storage.removeItem('id_token_claims_obj');
        this._storage.removeItem('id_token_expires_at');
        this._storage.removeItem('id_token_stored_at');
        this._storage.removeItem('access_token_stored_at');
    }

    // ------- Id Token //////////////////////////////////

    /* Checkes, whether there is a valid id_token.*/
    public hasValidIdToken(): boolean {
        if (this.getIdToken()) {
            const expiresAt = this._storage.getItem('id_token_expires_at');
            const now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }

            return true;
        }

        return false;
    }

    /* Store all info of the Id Token*/
    public storeIdToken(idToken: ParsedIdToken) {
        this._storage.setItem('id_token', idToken.idToken);
        this._storage.setItem('id_token_claims_obj', idToken.idTokenClaimsJson);
        this._storage.setItem('id_token_expires_at', '' + idToken.idTokenExpiresAt);
        this._storage.setItem('id_token_stored_at', '' + Date.now());
    }

    /* Returns the current id_token.*/
    public getIdToken(): string {
        return this._storage
            ? this._storage.getItem('id_token')
            : null;
    }

    /* Returns the expiration date of the id_token
     * as milliseconds since 1970.*/
    public getIdTokenExpiration(): number {
        if (!this._storage.getItem('id_token_expires_at')) {
            return null;
        }

        return parseInt(this._storage.getItem('id_token_expires_at'), 10);
    }

    /* Returns the Stored At of the id_token*/
    public getIdTokenStoredAt(): number {
        return parseInt(this._storage.getItem('id_token_stored_at'), 10);
    }

    /* Returns the received claims about the user, from id token.*/
    public getIdentityClaims(): object {
        const claims = this._storage.getItem('id_token_claims_obj');
        if (!claims) {
            return null;
        }
        return JSON.parse(claims);
    }

    // ------- Access Token //////////////////////////////

     /* Store the Access_token_expires_at.*/
     public storeAccessTokenExpiresAt(accessTokenExpiresAt: string): void {
        this._storage.setItem('access_token_expires_at', accessTokenExpiresAt);
    }

    /* Store the Access Token Stored At.*/
    public storeAccessTokenStoredAt(accessTokenStoredAt: string): void {
        this._storage.setItem('access_token_stored_at', accessTokenStoredAt);
    }

    /* Store the Access Token.*/
    public storeAccessToken(accessToken: string): void {
        this._storage.setItem('access_token', accessToken);
    }

    /* Checkes, whether there is a valid access_token.*/
    public hasValidAccessToken(): boolean {
        if (this.getAccessToken()) {
            const expiresAt = this._storage.getItem('access_token_expires_at');
            const now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }

            return true;
        }

        return false;
    }

    /* Returns the current access_token.*/
    public getAccessToken(): string {
        return this._storage.getItem('access_token');
    }

    /* Returns the expiration date of the access_token
     * as milliseconds since 1970*/
    public getAccessTokenExpiration(): number {
        if (!this._storage.getItem('access_token_expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('access_token_expires_at'), 10);
    }

    /* Returns the Stored at of the access_token*/
    public getAccessTokenStoredAt(): number {
        return parseInt(this._storage.getItem('access_token_stored_at'), 10);
    }

    // ------- Refresh Token //////////////////////////////

    /* Returns the current refresh_token.*/
    public getRefreshToken(): string {
        return this._storage.getItem('refresh_token');
    }

    /* Store the refresh_token.*/
    public storeRefreshToken(refreshToken: string): void {
        this._storage.setItem('refresh_token', refreshToken);
    }


    // ------- Granted Scopes //////////////////////////////

    /* Returns the granted scopes.*/
    public getGrantedScopes(): object {
        const scopes = this._storage.getItem('granted_scopes');
        if (!scopes) {
            return null;
        }
        return JSON.parse(scopes);
    }

    /* Store the Granted Scopes.*/
    public storeGrantedScopes(grantedScopes: string): void {
        this._storage.setItem('granted_scopes', grantedScopes);
    }

    // ------- Session State //////////////////////////////

    /* Store the Session State.*/
    public storeSessionState(sessionState: string): void {
        this._storage.setItem('session_state', sessionState);
    }

    /* Returns the Session State.*/
    public getSessionState(): string {
        return this._storage.getItem('session_state');
    }

    // ------- Nonce //////////////////////////////

    /* Returns the current refresh_token.*/
    public getNonce(): string {
        return this._storage.getItem('nonce');
    }

    /* Create and Store Nonce */
    public createAndSaveNonce(): string {
        const nonce = this.createNonce();
        this._storage.setItem('nonce', nonce);
        return nonce;
    }

    /* Create Nonce
    * rngUrl is a property of the class AuthConfig
    */
    protected createNonce(rngUrl: string = ''): string {

        if (rngUrl) {
            throw new Error('createNonce with rng-web-api has not been implemented so far');
        } else {
        let text = '';
        const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

        for (let i = 0; i < 40; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }
            return text;
        }
    }

    /* Validate the Nonce in Param State, comparinf to the nonce stored */
    private validateNonceForAccessToken(
        accessToken: string,
        nonceInState: string
    ): boolean {
        const savedNonce = this.getNonce();
        if (savedNonce !== nonceInState) {
            const err = 'validating access_token failed. wrong state/nonce.';
            console.error(err, savedNonce, nonceInState);
            return false;
        }
        return true;
    }
}
