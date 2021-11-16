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

import { Injectable } from '@angular/core';
import { from, Observable } from 'rxjs';
import { AlfrescoApiService, AppConfigService } from '@alfresco/adf-core';
import {
    QueryBody,
    ResultSetPaging,
    SearchApi
} from '@alfresco/js-api';
import { SearchConfiguration } from '../models/search-configuration.interface';
import { BaseQueryBuilderService } from './base-query-builder.service';

@Injectable({
    providedIn: 'root'
})
export abstract class SearchQueryBuilderService extends BaseQueryBuilderService {

    constructor(protected appConfig: AppConfigService) {
        super(appConfig);
    }

    public isFilterServiceActive(): boolean {
        return false;
    }

    public loadConfiguration(): SearchConfiguration {
        return this.appConfig.get<SearchConfiguration>('search');
    }

    abstract set searchQuery(word);

    // /*  Stream that emits the search configuration whenever the user change the search forms */
    // configUpdated: Subject<SearchConfiguration>;

    // /*  Stream that emits the query before search whenever user search  */
    // updated: Subject<QueryBody>;

    // /*  Stream that emits the results whenever user search  */
    // executed: Subject<ResultSetPaging>;

    // /*  Stream that emits the error whenever user search  */
    // error: Subject<any>;

    // /*  Stream that emits search forms  */
    // searchForms = new ReplaySubject<SearchForm[]>(1);

    // paging: { maxItems?: number; skipCount?: number };

    // userQuery: string;

    // categories: SearchCategory[] = [];
    // queryFragments: { [id: string]: string } = {};

    // /**
    //  * Builds the current query and triggers the `updated` event.
    //  */
    // abstract update(): void;

    // abstract resetToDefaults(): void;

    // abstract execute(queryBody?: QueryBody);

    // /**
    //  * Gets the primary sorting definition.
    //  * @returns The primary sorting definition
    //  */
    // abstract getPrimarySorting(): SearchSortingDefinition;

    // /**
    //  * Adds a filter query to the current query.
    //  * @param query Query string to add
    //  */
    // abstract addFilterQuery(query: string): void;
}

@Injectable()
export class SearchQueryBuilderServiceImpl extends SearchQueryBuilderService {

    constructor(appConfig: AppConfigService, private alfrescoApiService: AlfrescoApiService) {
        super(appConfig);
    }

    _searchApi: SearchApi;
    get searchApi(): SearchApi {
        this._searchApi = this._searchApi ?? new SearchApi(this.alfrescoApiService.getInstance());
        return this._searchApi;
    }

    _doSearch(queryBody: QueryBody): Observable<ResultSetPaging> {
        return from(this.searchApi.search(queryBody));
    }

    protected isOperator(input: string): boolean {
        if (input) {
            input = input.trim().toUpperCase();

            const operators = ['AND', 'OR'];
            return operators.includes(input);
        }
        return false;
    }

    protected formatFields(fields: string[], term: string): string {
        let prefix = '';
        let suffix = '*';

        if (term.startsWith('=')) {
            prefix = '=';
            suffix = '';
            term = term.substring(1);
        }

        return '(' + fields.map((field) => `${prefix}${field}:"${term}${suffix}"`).join(' OR ') + ')';
    }

    protected formatSearchQuery(userInput: string, fields = ['cm:name']) {
        if (!userInput) {
            return null;
        }

        if (/^http[s]?:\/\//.test(userInput)) {
            return this.formatFields(fields, userInput);
        }

        userInput = userInput.trim();

        if (userInput.includes(':') || userInput.includes('"')) {
            return userInput;
        }

        const words = userInput.split(' ');

        if (words.length > 1) {
            const separator = words.some(this.isOperator) ? ' ' : ' AND ';

            return words
            .map((term) => {
                if (this.isOperator(term)) {
                return term;
                }

                return this.formatFields(fields, term);
            })
            .join(separator);
        }

        return this.formatFields(fields, userInput);
    }

    set searchQuery(word) {
        const query = this.formatSearchQuery(word, this.config['aca:fields']);
        if (query) {
            this.userQuery = decodeURIComponent(query);
        }
    }
}
