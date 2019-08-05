import { MobileSsoHelper } from './mobile-sso-helper';
import { MobileSsoService } from './mobile-sso-service';
import { MobilessoStorageHelper } from './helper/mobilesso-storage-helper';
import { MobileSsoUrlHelper } from './helper/mobilesso-url-helper.service';
import { NgModule } from '@angular/core';

@NgModule({
    providers: [
        MobileSsoUrlHelper,
        MobilessoStorageHelper,
        MobileSsoService,
        MobileSsoHelper
    ]
})

export class MobileSsoModule { }
