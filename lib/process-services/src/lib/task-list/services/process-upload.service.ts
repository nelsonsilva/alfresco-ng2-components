/*!
 * @license
 * Copyright 2019 Alfresco Software, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { AlfrescoApiService, AppConfigService, DiscoveryApiService, UploadService } from '@alfresco/adf-core';
import { ActivitiContentApi } from '@alfresco/js-api';
import { Injectable } from '@angular/core';
import { throwError } from 'rxjs';

@Injectable({
    providedIn: 'root'
})
export class ProcessUploadService extends UploadService {

    contentApi: ActivitiContentApi;

    constructor(protected apiService: AlfrescoApiService, appConfigService: AppConfigService, discoveryApiService: DiscoveryApiService) {
        super(apiService, appConfigService, discoveryApiService);
        this.contentApi = new ActivitiContentApi(apiService.getInstance());
    }

    getUploadPromise(file: any): any {
        const opts = {
            isRelatedContent: true
        };
        const processInstanceId = file.options.parentId;
        const promise = this.contentApi.createRelatedContentOnProcessInstance(processInstanceId, file.file, opts);

        promise.catch((err) => this.handleError(err));

        return promise;
    }

    private handleError(error: any) {
        return throwError(error || 'Server error');
    }

}
