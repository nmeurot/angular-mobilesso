# Angular MobileSSO




## Install the componant

Run `npm install @aeroline_1025/angular-mobilesso` to install the package on your project.
## Configure Module
On the file `app.modules.ts`, add the MobileSSO Module
```
import { MobileSsoModule } from  '@aeroline_1025/angular-mobilesso';

@NgModule({
   imports: [
      MobileSsoModule
   ]
})
```
## Environment Configuration
Use the environment configuration file to pass the mandatory paramters to use the MobileSSO:
- issuer : issuer defined by the MobileSSO
- scope: Scope define for the project by MobileSSO, to retreive the Access Token 
- clientId: Client ID defined by MobileSSO to defined which clinet we are
- redirectUrl: Url declared on MobileSSO and associated to our ClientID, It will be the Url redirect by the mobile SSO to send Authorization Code (as Query parameter)
- autoRefreshAccessToken (boolean): Define if the Access Token is automatically updated by the Id Token, when it nearly expire

*This is an example :*
```
export const environment = {
	issuer:  '<URL Issuer (FedBroker)>',
	scope:  'SCO_<Project Scope>',
	clientId:  'CLI_<Project Client>',
	redirectUrl:  '<URL to redirect by MobileSSO>/',
	autoRefreshAccessToken:  true
}
```
There are the default properties to use to instanciate a new `AuthConfigMobileSSO` used by the componant angular-mobilsso

## How to authenticate

The only thing to do is to :
- Define the AuthConfigMobileSSO through the environment file
- Import the Mobile SSO Module on the app module
- Call the methode authenticate(...) from the class `MobileSsoHelper`

*This is the class to import and the signature of the method to use :*
```
import { MobileSsoHelper } from  '@aeroline_1025/angular-mobilesso';

public authenticate(config: AuthConfigMobileSSO,
                    loginServiceUrl: string,
                    showLogInfo = false,
                    @Optional() callback:  any):  void {}
```
- *config*: AuthConfigMobileSSO parameters
- *loginServiceUrl* : Url to our own service login to validate the Access Token retreived and validate login (and / or generate internal JWT application token)
- *showLogInfo*: Define if we display logs INFO or not
- *callback*: is an object with at least the method what to do more when Access Token is received. It is optionnal : `applyToken(data: TokenResponse): void;`
> **Exemple** of applyToken method :
>   ```
>       /**
>	     * Apply token from internal zone
>	     * @param data Token response
>	     */
>	    applyToken(data: TokenResponse): void {
>	        if (window.opener) {
>	            window.opener.my.app.applyTokenFromOutside(data);
>           } else {
>	            localStorage.setItem(this.KeyTokenStorageName, JSON.stringify(data));
>	            this.setCurrentTokenResponse(data); // It is a custom method to store some date information
>	            this.router.navigate(['']);
>	          }
>	    }


## Where to authenticate

The authentication has to be done on a Interceptor, where the method will be called to authenticate through the MobileSSO Helper

> **Exemple** of interceptor :
> In this example `this.userService.Authenticate(true);` is a custom method on a user service custom where the method `this.mobileSsoHelper.authenticate(GlobalConfiguration.getMobileSsoConfig(),
this.loginServiceUrl
true,
this.callback);` is called
>   ```
>  /**
> * Interception method
> * @param  request Http request
> * @param  next next action
> */
>  public  intercept (request:  HttpRequest<any>, next:  HttpHandler): Observable<HttpEvent<any>> {
>      this.Logger.info(`Process to request : ${request.url}`);
>      if (request.url  !==  this.loginServiceUrl) {
>          // Normal request (add current token)
>          request  =  this.addTokenHeaders(request);
>          if (this.userService.isTokenExpired()) {
>              this.Logger.info('Token is expired, ask a new token');
>              **this.userService.Authenticate(true)**;
>         } else {
>              // Execute request
>              return  next.handle(request)
>                                  .pipe(
>                                     map(res  =>  res),
>                                     catchError((err, caught) => {
>                                           if (err  instanceof  RedoException) {
>                                               throw  err;
>                                           }
>                                           if (err  instanceof  HttpErrorResponse) {
>                                                 this.Logger.warning('Error in HTTP interceptor');
>                                                 const  jsonParseError  =  'Http failure during parsing for';
>                                                 const  matches  =  err.message.match(new  RegExp(jsonParseError, 'ig'));
>                                                // return of(null);
>                                                if (err.status  ===  200  &&  matches.length  ===  1) {
>                                                     // return obs that completes;
>                                                     this.Logger.info('Skip http failure for parsing, response type is not JSON however the format seems good.');
>                                                     throw(err.error.text);
>                                               } else {
>                                                     if (err.status  ===  401) {
>                                                         // Authentication error
>                                                         this.Logger.error(`Authentication error : ${err.message}`);
>                                                         **this.userService.Authenticate(true)**;
>                                                         throw  new  AutorizationException();
>                                                     } else {
>                                                          this.Logger.error(`Application communication error (code ${err.status}) : ${err.message}`);
>                                                          throw(err);
>                                                     }
>                                               }
>                                          }
>                                          return  caught;
>                                     }));
>            }
>       }
>       return  next.handle(request);
> } 
