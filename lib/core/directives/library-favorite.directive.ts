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

import { Directive, HostListener, Input, OnChanges, Output, EventEmitter } from '@angular/core';
import { SiteBody, FavoriteBody, FavoriteEntry, Site, FavoritesApi } from '@alfresco/js-api';
import { AlfrescoApiService } from '../services/alfresco-api.service';

export interface LibraryEntity {
    entry: Site;
    isLibrary: boolean;
    isFavorite: boolean;
}

@Directive({
    selector: '[adf-favorite-library]',
    exportAs: 'favoriteLibrary'
})
export class LibraryFavoriteDirective implements OnChanges {
    @Input('adf-favorite-library')
    library: LibraryEntity = null;

    @Output() toggle = new EventEmitter<any>();
    // tslint:disable-next-line: no-output-native
    @Output() error = new EventEmitter<any>();

    private targetLibrary = null;
    private favoritesApi: FavoritesApi;

    @HostListener('click')
    onClick() {
        const guid = this.targetLibrary.entry.guid;

        if (this.targetLibrary.isFavorite) {
            this.removeFavorite(guid);
        } else {
            this.addFavorite({
                target: {
                    site: {
                        guid
                    }
                }
            });
        }
    }

    constructor(private alfrescoApiService: AlfrescoApiService) {
        this.favoritesApi = new FavoritesApi(this.alfrescoApiService.getInstance());
    }

    ngOnChanges(changes) {
        if (!changes.library.currentValue) {
            this.targetLibrary = null;
            return;
        }

        this.targetLibrary = changes.library.currentValue;
        this.markFavoriteLibrary(changes.library.currentValue);
    }

    isFavorite(): boolean {
        return this.targetLibrary && this.targetLibrary.isFavorite;
    }

    private async markFavoriteLibrary(library: LibraryEntity) {
        if (this.targetLibrary.isFavorite === undefined) {
            try {
                await this.favoritesApi.getFavoriteSite('-me-', library.entry.id);
                this.targetLibrary.isFavorite = true;
            } catch {
                this.targetLibrary.isFavorite = false;
            }
        } else {
            this.targetLibrary = library;
        }
    }

    private addFavorite(favoriteBody: FavoriteBody) {
        this.favoritesApi
            .createFavorite('-me-', favoriteBody)
            .then((libraryEntry: FavoriteEntry) => {
                this.targetLibrary.isFavorite = true;
                this.toggle.emit(libraryEntry);
            })
            .catch((error) => this.error.emit(error));
    }

    private removeFavorite(favoriteId: string) {
        this.favoritesApi
            .deleteFavorite('-me-', favoriteId)
            .then((libraryBody: SiteBody) => {
                this.targetLibrary.isFavorite = false;
                this.toggle.emit(libraryBody);
            })
            .catch((error) => this.error.emit(error));
    }
}
