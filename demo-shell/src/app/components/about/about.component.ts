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

import { Component, OnInit } from '@angular/core';
import pkg from '../../../../../package.json';
import { AppConfigService } from '@alfresco/adf-core';

@Component({
    selector: 'app-about-page',
    templateUrl: './about.component.html',
    styleUrls: ['./about.component.scss']
})
export class AboutComponent implements OnInit {
    url = `https://github.com/Alfresco/${pkg.name}/commits/${pkg.commit}`;
    version = pkg.version;
    dependencies = pkg.dependencies;
    showExtensions = true;
    application = '';

    constructor(private appConfigService: AppConfigService) {}

    ngOnInit() {
        this.application = this.appConfigService.get<string>(
            'application.name'
        );
    }
}
