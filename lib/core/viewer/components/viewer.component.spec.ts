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

import { Location } from '@angular/common';
import { SpyLocation } from '@angular/common/testing';
import { Component } from '@angular/core';
import { ComponentFixture, TestBed, fakeAsync, tick } from '@angular/core/testing';
import { AlfrescoApiService, RenditionsService } from '../../services';

import { throwError } from 'rxjs';
import { EventMock } from '../../mock/event.mock';
import { RenderingQueueServices } from '../services/rendering-queue.services';
import { ViewerComponent } from './viewer.component';
import { setupTestBed } from '../../testing/setup-test-bed';
import { NodeEntry, VersionEntry } from '@alfresco/js-api';
import { CoreTestingModule } from '../../testing/core.testing.module';
import { TranslateModule } from '@ngx-translate/core';
import { MatDialog } from '@angular/material/dialog';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { UploadService } from '../../services/upload.service';
import { FileModel } from '../../models';

@Component({
    selector: 'adf-viewer-container-toolbar',
    template: `
        <adf-viewer>
            <adf-viewer-toolbar>
                <div class="custom-toolbar-element"></div>
            </adf-viewer-toolbar>
        </adf-viewer>
    `
})
class ViewerWithCustomToolbarComponent {
}

@Component({
    selector: 'adf-viewer-container-toolbar-actions',
    template: `
        <adf-viewer>
            <adf-viewer-toolbar-actions>
                <button mat-icon-button id="custom-button">
                    <mat-icon>alarm</mat-icon>
                </button>
            </adf-viewer-toolbar-actions>
        </adf-viewer>
    `
})
class ViewerWithCustomToolbarActionsComponent {
}

@Component({
    selector: 'adf-viewer-container-sidebar',
    template: `
        <adf-viewer>
            <adf-viewer-sidebar>
                <div class="custom-sidebar"></div>
            </adf-viewer-sidebar>
        </adf-viewer>
    `
})
class ViewerWithCustomSidebarComponent {
}

@Component({
    selector: 'adf-dialog-dummy',
    template: ``
})
class DummyDialogComponent {
}

@Component({
    selector: 'adf-viewer-container-open-with',
    template: `
        <adf-viewer>
            <adf-viewer-open-with>
                <button mat-menu-item>
                    <mat-icon>dialpad</mat-icon>
                    <span>Option 1</span>
                </button>
                <button mat-menu-item disabled>
                    <mat-icon>voicemail</mat-icon>
                    <span>Option 2</span>
                </button>
                <button mat-menu-item>
                    <mat-icon>notifications_off</mat-icon>
                    <span>Option 3</span>
                </button>
            </adf-viewer-open-with>
        </adf-viewer>
    `
})
class ViewerWithCustomOpenWithComponent {
}

@Component({
    selector: 'adf-viewer-container-more-actions',
    template: `
        <adf-viewer>
            <adf-viewer-more-actions>
                <button mat-menu-item>
                    <mat-icon>dialpad</mat-icon>
                    <span>Action One</span>
                </button>
                <button mat-menu-item disabled>
                    <mat-icon>voicemail</mat-icon>
                    <span>Action Two</span>
                </button>
                <button mat-menu-item>
                    <mat-icon>notifications_off</mat-icon>
                    <span>Action Three</span>
                </button>
            </adf-viewer-more-actions>
        </adf-viewer>
    `
})
class ViewerWithCustomMoreActionsComponent {
}
describe('ViewerComponent', () => {

    let component: ViewerComponent;
    let fixture: ComponentFixture<ViewerComponent>;
    let alfrescoApiService: AlfrescoApiService;
    let element: HTMLElement;
    let dialog: MatDialog;
    let uploadService: UploadService;

    setupTestBed({
        imports: [
            NoopAnimationsModule,
            TranslateModule.forRoot(),
            CoreTestingModule
        ],
        declarations: [
            ViewerWithCustomToolbarComponent,
            ViewerWithCustomSidebarComponent,
            ViewerWithCustomOpenWithComponent,
            ViewerWithCustomMoreActionsComponent,
            ViewerWithCustomToolbarActionsComponent
        ],
        providers: [
            {
                provide: RenditionsService, useValue: {
                    getRendition: () => {
                        return throwError('thrown');
                    }
                }
            },
            RenderingQueueServices,
            { provide: Location, useClass: SpyLocation },
            MatDialog
        ]
    });

    beforeEach(() => {
        fixture = TestBed.createComponent(ViewerComponent);
        element = fixture.nativeElement;
        component = fixture.componentInstance;

        uploadService = TestBed.inject(UploadService);
        alfrescoApiService = TestBed.inject(AlfrescoApiService);
        dialog = TestBed.inject(MatDialog);
    });

    describe('Extension Type Test', () => {

        afterEach(() => {
            fixture.destroy();
        });

        it('should  extension file pdf  be loaded', (done) => {
            component.urlFile = 'fake-test-file.pdf';
            component.ngOnChanges();
            fixture.detectChanges();

            fixture.whenStable().then(() => {
                fixture.detectChanges();
                expect(element.querySelector('adf-pdf-viewer')).not.toBeNull();
                done();
            });
        });

        it('should  extension file png be loaded', (done) => {
            component.urlFile = 'fake-url-file.png';
            component.ngOnChanges();
            fixture.detectChanges();

            fixture.whenStable().then(() => {
                fixture.detectChanges();
                expect(element.querySelector('#viewer-image')).not.toBeNull();
                done();
            });
        });

        it('should extension file mp4 be loaded', (done) => {
            component.urlFile = 'fake-url-file.mp4';
            component.ngOnChanges();
            fixture.detectChanges();

            fixture.whenStable().then(() => {
                fixture.detectChanges();
                expect(element.querySelector('adf-media-player')).not.toBeNull();
                done();
            });
        });

        it('should extension file txt be loaded', (done) => {
            component.urlFile = 'fake-test-file.txt';
            component.ngOnChanges();
            fixture.detectChanges();

            fixture.whenStable().then(() => {
                fixture.detectChanges();
                expect(element.querySelector('adf-txt-viewer')).not.toBeNull();
                done();
            });
        });

        it('should display [unknown format] for unsupported extensions', (done) => {
            component.urlFile = 'fake-url-file.unsupported';
            component.mimeType = '';
            component.ngOnChanges();
            fixture.detectChanges();

            fixture.whenStable().then(() => {
                fixture.detectChanges();
                expect(element.querySelector('adf-viewer-unknown-format')).toBeDefined();
                done();
            });
        });
    });

    describe('MimeType handling', () => {

        afterEach(() => {
            fixture.destroy();
        });

        it('should display an image file identified by mimetype when the filename has no extension', (done) => {
            component.urlFile = 'fake-content-img';
            component.mimeType = 'image/png';
            fixture.detectChanges();
            component.ngOnChanges();

            fixture.whenStable().then(() => {
                fixture.detectChanges();
                expect(element.querySelector('#viewer-image')).not.toBeNull();
                done();
            });
        });

        it('should display a image file identified by mimetype when the file extension is wrong', (done) => {
            component.urlFile = 'fake-content-img.bin';
            component.mimeType = 'image/png';
            fixture.detectChanges();
            component.ngOnChanges();

            fixture.whenStable().then(() => {
                fixture.detectChanges();
                expect(element.querySelector('#viewer-image')).not.toBeNull();
                done();
            });
        });

        it('should display the txt viewer if the file identified by mimetype is a txt when the filename has wrong extension', (done) => {
            component.urlFile = 'fake-content-txt.bin';
            component.mimeType = 'text/plain';
            fixture.detectChanges();
            component.ngOnChanges();

            fixture.whenStable().then(() => {
                fixture.detectChanges();
                expect(element.querySelector('adf-txt-viewer')).not.toBeNull();
                done();
            });
        });

        it('should node without content show unkonwn', (done) => {
            const displayName = 'the-name';
            const contentUrl = '/content/url/path';

            component.nodeId = '12';
            component.urlFile = null;
            component.displayName = null;
            spyOn(component['nodesApi'], 'getNode').and.returnValue(Promise.resolve({
                id: 'fake-node',
                entry: { content: { name: displayName, id: '12' } }
            }));

            spyOn(component['contentApi'], 'getContentUrl').and.returnValue(contentUrl);

            component.ngOnChanges();
            fixture.whenStable().then(() => {
                fixture.detectChanges();
                expect(element.querySelector('adf-viewer-unknown-format')).toBeDefined();
                done();
            });
        });

        it('should display the media player if the file identified by mimetype is a media when the filename has wrong extension', (done) => {
            component.urlFile = 'fake-content-video.bin';
            component.mimeType = 'video/mp4';
            fixture.detectChanges();
            component.ngOnChanges();

            fixture.whenStable().then(() => {
                fixture.detectChanges();
                expect(element.querySelector('adf-media-player')).not.toBeNull();
                done();
            });
        }, 25000);

        it('should display the media player if the file identified by mimetype is a media when the filename has no extension', (done) => {
            component.urlFile = 'fake-content-video';
            component.mimeType = 'video/mp4';
            fixture.detectChanges();
            component.ngOnChanges();

            fixture.whenStable().then(() => {
                fixture.detectChanges();
                expect(element.querySelector('adf-media-player')).not.toBeNull();
                done();
            });
        }, 25000);

        it('should display a PDF file identified by mimetype when the filename has no extension', (done) => {
            component.urlFile = 'fake-content-pdf';
            component.mimeType = 'application/pdf';
            fixture.detectChanges();
            component.ngOnChanges();

            fixture.whenStable().then(() => {
                fixture.detectChanges();
                expect(element.querySelector('adf-pdf-viewer')).not.toBeNull();
                done();
            });

        }, 25000);

        it('should display a PDF file identified by mimetype when the file extension is wrong', (done) => {
            component.urlFile = 'fake-content-pdf.bin';
            component.mimeType = 'application/pdf';
            component.ngOnChanges();
            fixture.detectChanges();
            fixture.whenStable().then(() => {
                fixture.detectChanges();
                expect(element.querySelector('adf-pdf-viewer')).not.toBeNull();
                done();
            });
        }, 25000);
    });

    it('should change display name every time node changes', fakeAsync(() => {
        spyOn(component['nodesApi'], 'getNode').and.returnValues(
            Promise.resolve(new NodeEntry({ entry: { name: 'file1', content: {} } })),
            Promise.resolve(new NodeEntry({ entry: { name: 'file2', content: {} } }))
        );

        component.urlFile = null;
        component.displayName = null;
        component.blobFile = null;
        component.showViewer = true;

        component.nodeId = 'id1';
        component.ngOnChanges();
        tick();

        expect(component.fileTitle).toBe('file1');

        component.nodeId = 'id2';
        component.ngOnChanges();
        tick();

        expect(component.fileTitle).toBe('file2');
    }));

    it('should append version of the file to the file content URL', fakeAsync(() => {
        spyOn(component['nodesApi'], 'getNode').and.returnValue(
            Promise.resolve(new NodeEntry({
                entry: {
                    name: 'file1',
                    content: {},
                    properties: { 'cm:versionLabel': '10' }
                }
            }))
        );
        spyOn(component['versionsApi'], 'getVersion').and.returnValue(Promise.resolve(undefined));

        component.nodeId = 'id1';
        component.urlFile = null;
        component.displayName = null;
        component.blobFile = null;
        component.showViewer = true;

        component.versionId = null;
        component.ngOnChanges();
        tick();

        expect(component.fileTitle).toBe('file1');
        expect(component.urlFileContent).toContain('/public/alfresco/versions/1/nodes/id1/content?attachment=false&10');
    }));

    it('should change display name every time node\`s version changes', fakeAsync(() => {
        spyOn(component['nodesApi'], 'getNode').and.returnValue(
            Promise.resolve(new NodeEntry({ entry: { name: 'node1', content: {} } }))
        );

        spyOn(component['versionsApi'], 'getVersion').and.returnValues(
            Promise.resolve(new VersionEntry({ entry: { name: 'file1', content: {} } })),
            Promise.resolve(new VersionEntry({ entry: { name: 'file2', content: {} } }))
        );

        component.nodeId = 'id1';
        component.urlFile = null;
        component.displayName = null;
        component.blobFile = null;
        component.showViewer = true;

        component.versionId = '1.0';
        component.ngOnChanges();
        tick();

        expect(component.fileTitle).toBe('file1');

        component.versionId = '1.1';
        component.ngOnChanges();
        tick();

        expect(component.fileTitle).toBe('file2');
    }));

    it('should update node only if node name changed', fakeAsync(() => {
        spyOn(component['nodesApi'], 'getNode').and.returnValues(
            Promise.resolve(new NodeEntry({ entry: { name: 'file1', content: {} } }))
        );
        spyOn(component['contentApi'], 'getContentUrl').and.returnValues('http://iam-fake.url');
        spyOn(component, 'getViewerTypeByExtension').and.returnValue('pdf');

        component.urlFile = null;
        component.displayName = null;
        component.blobFile = null;
        component.showViewer = true;

        component.nodeId = 'id1';
        fixture.detectChanges();
        component.ngOnChanges();
        tick();

        expect(component.fileTitle).toBe('file1');

        alfrescoApiService.nodeUpdated.next(<any> { id: 'id1', name: 'file2' });
        fixture.detectChanges();
        expect(component.fileTitle).toBe('file2');

        alfrescoApiService.nodeUpdated.next(<any> { id: 'id1', name: 'file3' });
        fixture.detectChanges();
        expect(component.fileTitle).toBe('file3');

        alfrescoApiService.nodeUpdated.next(<any> { id: 'id2', name: 'file4' });
        fixture.detectChanges();
        expect(component.fileTitle).toBe('file3');
        expect(component.nodeId).toBe('id1');
    }));

    describe('Viewer Example Component Rendering', () => {

        it('should use custom toolbar', (done) => {
            const customFixture = TestBed.createComponent(ViewerWithCustomToolbarComponent);
            const customElement: HTMLElement = customFixture.nativeElement;

            customFixture.detectChanges();
            fixture.whenStable().then(() => {
                expect(customElement.querySelector('.custom-toolbar-element')).toBeDefined();
                done();
            });
        });

        it('should use custom toolbar actions', (done) => {
            const customFixture = TestBed.createComponent(ViewerWithCustomToolbarActionsComponent);
            const customElement: HTMLElement = customFixture.nativeElement;

            customFixture.detectChanges();
            fixture.whenStable().then(() => {
                expect(customElement.querySelector('#custom-button')).toBeDefined();
                done();
            });
        });

        it('should use custom info drawer', (done) => {
            const customFixture = TestBed.createComponent(ViewerWithCustomSidebarComponent);
            const customElement: HTMLElement = customFixture.nativeElement;

            customFixture.detectChanges();

            fixture.whenStable().then(() => {
                expect(customElement.querySelector('.custom-info-drawer-element')).toBeDefined();
                done();
            });
        });

        it('should use custom open with menu', (done) => {
            const customFixture = TestBed.createComponent(ViewerWithCustomOpenWithComponent);
            const customElement: HTMLElement = customFixture.nativeElement;

            customFixture.detectChanges();

            fixture.whenStable().then(() => {
                expect(customElement.querySelector('.adf-viewer-container-open-with')).toBeDefined();
                done();
            });
        });

        it('should use custom more actions menu', (done) => {
            const customFixture = TestBed.createComponent(ViewerWithCustomMoreActionsComponent);
            const customElement: HTMLElement = customFixture.nativeElement;

            customFixture.detectChanges();

            fixture.whenStable().then(() => {
                expect(customElement.querySelector('.adf-viewer-container-more-actions')).toBeDefined();
                done();
            });

        });
    });

    describe('Base component', () => {

        beforeEach(() => {
            component.showToolbar = true;
            component.urlFile = 'fake-test-file.pdf';
            component.mimeType = 'application/pdf';

            fixture.detectChanges();
        });

        describe('SideBar Test', () => {

            it('should NOT display sidebar if is not allowed', (done) => {
                component.showRightSidebar = true;
                component.allowRightSidebar = false;
                fixture.detectChanges();

                fixture.whenStable().then(() => {
                    const sidebar = element.querySelector('#adf-right-sidebar');
                    expect(sidebar).toBeNull();
                    done();
                });
            });

            it('should display sidebar on the right side', (done) => {
                component.allowRightSidebar = true;
                component.showRightSidebar = true;
                fixture.detectChanges();

                fixture.whenStable().then(() => {
                    const sidebar = element.querySelector('#adf-right-sidebar');
                    expect(getComputedStyle(sidebar).order).toEqual('4');
                    done();
                });
            });

            it('should NOT display left sidebar if is not allowed', (done) => {
                component.showLeftSidebar = true;
                component.allowLeftSidebar = false;
                fixture.detectChanges();

                fixture.whenStable().then(() => {
                    const sidebar = element.querySelector('#adf-left-sidebar');
                    expect(sidebar).toBeNull();
                    done();
                });

            });

            it('should display sidebar on the left side', (done) => {
                component.allowLeftSidebar = true;
                component.showLeftSidebar = true;
                fixture.detectChanges();

                fixture.whenStable().then(() => {
                    const sidebar = element.querySelector('#adf-left-sidebar');
                    expect(getComputedStyle(sidebar).order).toEqual('1');
                    done();
                });
            });
        });

        describe('Toolbar', () => {

            it('should render fullscreen button', () => {
                expect(element.querySelector('[data-automation-id="adf-toolbar-fullscreen"]')).toBeDefined();
            });

            it('should not render fullscreen button', (done) => {
                component.allowFullScreen = false;
                fixture.detectChanges();

                fixture.whenStable().then(() => {
                    expect(element.querySelector('[data-automation-id="adf-toolbar-fullscreen"]')).toBeNull();
                    done();
                });
            });

            it('should render default download button', (done) => {
                component.allowDownload = true;

                fixture.whenStable().then(() => {
                    expect(element.querySelector('[data-automation-id="adf-toolbar-download"]')).toBeDefined();
                    done();
                });
            });

            it('should not render default download button', (done) => {
                component.allowDownload = false;
                fixture.detectChanges();

                fixture.whenStable().then(() => {
                    expect(element.querySelector('[data-automation-id="adf-toolbar-download"]')).toBeNull();
                    done();
                });
            });

            it('should render default print button', (done) => {
                component.allowPrint = true;
                fixture.detectChanges();

                fixture.whenStable().then(() => {
                    expect(element.querySelector('[data-automation-id="adf-toolbar-print"]')).toBeDefined();
                    done();
                });
            });

            it('should not render default print button', (done) => {
                component.allowPrint = false;
                fixture.detectChanges();

                fixture.whenStable().then(() => {
                    expect(element.querySelector('[data-automation-id="adf-toolbar-print"]')).toBeNull();
                    done();
                });
            });

            it('should invoke print action with the toolbar button', (done) => {
                component.allowPrint = true;
                fixture.detectChanges();

                spyOn(component, 'printContent').and.stub();

                const button: HTMLButtonElement = element.querySelector('[data-automation-id="adf-toolbar-print"]') as HTMLButtonElement;
                button.click();

                fixture.whenStable().then(() => {
                    expect(component.printContent).toHaveBeenCalled();
                    done();
                });
            });

            it('should raise the print event with the toolbar button', (done) => {
                component.allowPrint = true;
                fixture.detectChanges();

                component.print.subscribe((e) => {
                    expect(e).not.toBeNull();
                    done();
                });

                const button: HTMLButtonElement = element.querySelector('[data-automation-id="adf-toolbar-print"]') as HTMLButtonElement;
                button.click();
            });

            it('should get and assign node for download', (done) => {
                component.nodeId = '12';
                component.urlFile = '';
                const displayName = 'the-name';
                const nodeDetails = {
                    id: 'fake-node',
                    entry: { name: displayName, id: '12', content: { mimeType: 'txt' } }
                };

                const contentUrl = '/content/url/path';

                spyOn(component['nodesApi'], 'getNode').and.returnValue(Promise.resolve(nodeDetails));
                spyOn(component['contentApi'], 'getContentUrl').and.returnValue(contentUrl);

                component.ngOnChanges();
                fixture.whenStable().then(() => {
                    fixture.detectChanges();
                    expect(component.nodeEntry).toBe(nodeDetails);
                    done();
                });
            });

            it('should render close viewer button if it is not a shared link', (done) => {
                fixture.detectChanges();
                fixture.whenStable().then(() => {
                    fixture.detectChanges();
                    expect(element.querySelector('[data-automation-id="adf-toolbar-back"]')).toBeDefined();
                    expect(element.querySelector('[data-automation-id="adf-toolbar-back"]')).not.toBeNull();
                    done();
                });
            });

            it('should emit `showViewerChange` event on close', async () => {
                spyOn(component.showViewerChange, 'emit');

                const button: HTMLButtonElement = element.querySelector('[data-automation-id="adf-toolbar-back"]') as HTMLButtonElement;
                button.click();

                fixture.detectChanges();
                await fixture.whenStable();

                expect(component.showViewerChange.emit).toHaveBeenCalled();
            });

            it('should not render close viewer button if it is a shared link', (done) => {
                spyOn(component['sharedLinksApi'], 'getSharedLink')
                    .and.returnValue(Promise.reject({}));

                component.sharedLinkId = 'the-Shared-Link-id';
                component.urlFile = null;
                component.mimeType = null;

                component.ngOnChanges();
                fixture.whenStable().then(() => {
                    fixture.detectChanges();
                    expect(element.querySelector('[data-automation-id="adf-toolbar-back"]')).toBeNull();
                    done();
                });
            });

        });

        describe('View', () => {

            describe('Overlay mode true', () => {

                beforeEach(() => {
                    component.overlayMode = true;
                    fixture.detectChanges();
                });

                it('should header be present if is overlay mode', () => {
                    expect(element.querySelector('.adf-viewer-toolbar')).not.toBeNull();
                });

                it('should Name File be present if is overlay mode ', (done) => {
                    component.ngOnChanges();
                    fixture.detectChanges();
                    fixture.whenStable().then(() => {
                        fixture.detectChanges();
                        expect(element.querySelector('#adf-viewer-display-name').textContent).toEqual('fake-test-file.pdf');
                        done();
                    });
                });

                it('should Close button be present if overlay mode', (done) => {
                    fixture.detectChanges();
                    fixture.whenStable().then(() => {
                        fixture.detectChanges();
                        expect(element.querySelector('.adf-viewer-close-button')).not.toBeNull();
                        done();
                    });
                });

                it('should Click on close button hide the viewer', (done) => {
                    const closebutton: any = element.querySelector('.adf-viewer-close-button');
                    closebutton.click();
                    fixture.detectChanges();

                    fixture.whenStable().then(() => {
                        expect(element.querySelector('.adf-viewer-content')).toBeNull();
                        done();
                    });
                });

                it('should Esc button hide the viewer', (done) => {
                    EventMock.keyDown(27);
                    fixture.detectChanges();

                    fixture.whenStable().then(() => {
                        expect(element.querySelector('.adf-viewer-content')).toBeNull();
                        done();
                    });
                });

                it('should not close the viewer on Escape event if dialog was opened', (done) => {
                    const event = new KeyboardEvent('keydown', {
                        bubbles: true,
                        keyCode: 27
                    } as KeyboardEventInit);
                    const dialogRef = dialog.open(DummyDialogComponent);

                    dialogRef.afterClosed().subscribe(() => {
                        document.body.dispatchEvent(event);
                        fixture.detectChanges();
                        expect(element.querySelector('.adf-viewer-content')).toBeNull();
                        done();
                    });

                    fixture.detectChanges();

                    document.body.dispatchEvent(event);
                    fixture.detectChanges();
                    expect(element.querySelector('.adf-viewer-content')).not.toBeNull();
                });
            });

            describe('Overlay mode false', () => {

                beforeEach(() => {
                    component.overlayMode = false;
                    fixture.detectChanges();
                });

                it('should Esc button not hide the viewer if is not overlay mode', (done) => {
                    EventMock.keyDown(27);
                    fixture.detectChanges();

                    fixture.whenStable().then(() => {
                        expect(element.querySelector('.adf-viewer-content')).not.toBeNull();
                        done();
                    });
                });
            });
        });

        describe('Attribute', () => {

            it('should Url or nodeId be mandatory', () => {
                component.showViewer = true;
                component.nodeId = undefined;
                component.urlFile = undefined;

                expect(() => {
                    component.ngOnChanges();
                }).toThrow();
            });

            it('should FileNodeId present not thrown any error ', () => {
                component.showViewer = true;
                component.nodeId = 'file-node-id';
                component.urlFile = undefined;

                expect(() => {
                    component.ngOnChanges();
                }).not.toThrow();
            });

            it('should  urlFile present not thrown any error ', () => {
                component.showViewer = true;
                component.nodeId = undefined;

                expect(() => {
                    component.ngOnChanges();
                }).not.toThrow();
            });

            it('should showViewer default value  be true', () => {
                expect(component.showViewer).toBe(true);
            });

            it('should viewer be hide if showViewer value is false', () => {
                component.showViewer = false;

                fixture.detectChanges();
                expect(element.querySelector('.adf-viewer-content')).toBeNull();
            });
        });

        describe('error handling', () => {

            it('should show unknown view when node file not found', (done) => {
                spyOn(component['nodesApi'], 'getNode')
                    .and.returnValue(Promise.reject({}));

                component.nodeId = 'the-node-id-of-the-file-to-preview';
                component.urlFile = null;
                component.mimeType = null;

                component.ngOnChanges();
                fixture.whenStable().then(() => {
                    fixture.detectChanges();
                    expect(element.querySelector('adf-viewer-unknown-format')).not.toBeNull();
                    done();
                });
            });

            it('should show unknown view when sharedLink file not found', (done) => {
                spyOn(component['sharedLinksApi'], 'getSharedLink')
                    .and.returnValue(Promise.reject({}));

                component.sharedLinkId = 'the-Shared-Link-id';
                component.urlFile = null;
                component.mimeType = null;

                component.ngOnChanges();
                fixture.whenStable().then(() => {
                    fixture.detectChanges();
                    expect(element.querySelector('adf-viewer-unknown-format')).not.toBeNull();
                    done();
                });

            });

            it('should raise an event when the shared link is invalid', (done) => {
                spyOn(component['sharedLinksApi'], 'getSharedLink')
                    .and.returnValue(Promise.reject({}));

                component.invalidSharedLink.subscribe(() => {
                    done();
                });

                component.sharedLinkId = 'the-Shared-Link-id';
                component.urlFile = null;
                component.mimeType = null;

                component.ngOnChanges();
            });

            it('should swicth to the unkwown template if the type specific viewers throw an error', (done) => {
                component.urlFile = 'fake-url-file.icns';
                component.mimeType = 'image/png';
                component.ngOnChanges();
                fixture.detectChanges();

                component.onUnsupportedFile();
                fixture.detectChanges();
                fixture.whenStable().then(() => {
                    fixture.detectChanges();
                    expect(element.querySelector('adf-viewer-unknown-format')).toBeDefined();
                    done();
                });
            });

        });

        describe('Events', () => {

            it('should if the extension change extension Change event be fired ', (done) => {

                component.extensionChange.subscribe((fileExtension) => {
                    expect(fileExtension).toEqual('png');
                    done();
                });

                component.urlFile = 'fake-url-file.png';

                component.ngOnChanges();
            });

            it('should update version when emitted by image-viewer and user has update permissions', () => {
                spyOn(uploadService, 'uploadFilesInTheQueue').and.callFake(() => {
                });
                spyOn(uploadService, 'addToQueue');
                component.readOnly = false;
                component.nodeEntry = new NodeEntry({
                    entry: {
                        name: 'fakeImage.png',
                        id: '12',
                        content: { mimeType: 'img/png' }
                    }
                });
                const data = atob('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==');
                const fakeBlob = new Blob([data], { type: 'image/png' });
                const newImageFile: File = new File([fakeBlob], component?.nodeEntry?.entry?.name, { type: component?.nodeEntry?.entry?.content?.mimeType });
                const newFile = new FileModel(
                    newImageFile,
                    {
                        majorVersion: false,
                        newVersion: true,
                        parentId: component?.nodeEntry?.entry?.parentId,
                        nodeType: component?.nodeEntry?.entry?.content?.mimeType
                    },
                    component.nodeEntry.entry?.id
                );
                component.onSubmitFile(fakeBlob);
                fixture.detectChanges();

                expect(uploadService.addToQueue).toHaveBeenCalledWith(...[newFile]);
                expect(uploadService.uploadFilesInTheQueue).toHaveBeenCalled();
            });

            it('should not update version when emitted by image-viewer and user doesn`t have update permissions', () => {
                spyOn(uploadService, 'uploadFilesInTheQueue').and.callFake(() => {
                });
                component.readOnly = true;
                component.nodeEntry = new NodeEntry({
                    entry: {
                        name: 'fakeImage.png',
                        id: '12',
                        content: { mimeType: 'img/png' }
                    }
                });
                const data = atob('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==');
                const fakeBlob = new Blob([data], { type: 'image/png' });
                component.onSubmitFile(fakeBlob);
                fixture.detectChanges();

                expect(uploadService.uploadFilesInTheQueue).not.toHaveBeenCalled();
            });
        });

        describe('display name property override by urlFile', () => {

            it('should displayName override the default name if is present and urlFile is set', (done) => {
                component.urlFile = 'fake-test-file.pdf';
                component.displayName = 'test name';
                fixture.detectChanges();
                component.ngOnChanges();

                fixture.whenStable().then(() => {
                    fixture.detectChanges();
                    expect(element.querySelector('#adf-viewer-display-name').textContent).toEqual('test name');
                    done();
                });
            });

            it('should use the urlFile name if displayName is NOT set and urlFile is set', (done) => {
                component.urlFile = 'fake-test-file.pdf';
                component.displayName = null;
                fixture.detectChanges();
                component.ngOnChanges();

                fixture.whenStable().then(() => {
                    fixture.detectChanges();
                    expect(element.querySelector('#adf-viewer-display-name').textContent).toEqual('fake-test-file.pdf');
                    done();
                });
            });
        });

        describe('display name property override by blobFile', () => {

            it('should displayName override the name if is present and blobFile is set', (done) => {
                component.displayName = 'blob file display name';
                component.blobFile = new Blob(['This is my blob content'], { type: 'text/plain' });
                fixture.detectChanges();
                component.ngOnChanges();

                fixture.whenStable().then(() => {
                    fixture.detectChanges();
                    expect(element.querySelector('#adf-viewer-display-name').textContent).toEqual('blob file display name');
                    done();
                });
            });

            it('should show uknownn name if displayName is NOT set and blobFile is set', (done) => {
                component.displayName = null;
                component.blobFile = new Blob(['This is my blob content'], { type: 'text/plain' });
                fixture.detectChanges();
                component.ngOnChanges();

                fixture.whenStable().then(() => {
                    fixture.detectChanges();
                    expect(element.querySelector('#adf-viewer-display-name').textContent).toEqual('Unknown');
                    done();
                });
            });
        });

        describe('display name property override by nodeId', () => {

            const contentUrl = '/content/url/path';
            const nodeDetails = new NodeEntry({ entry: { name: 'node-id-name', id: '12', content: { mimeType: 'txt' } } });

            it('should use the node name if displayName is NOT set and nodeId is set', (done) => {
                spyOn(component['nodesApi'], 'getNode').and.returnValue(Promise.resolve(nodeDetails));
                spyOn(component['contentApi'], 'getContentUrl').and.returnValue(contentUrl);

                component.nodeId = '12';
                component.urlFile = null;
                component.displayName = 'the-name';

                component.ngOnChanges();
                fixture.whenStable().then(() => {
                    fixture.detectChanges();
                    expect(element.querySelector('#adf-viewer-display-name').textContent).toEqual('the-name');
                    done();
                });
            });
        });
    });

    describe('Viewer component - Full Screen Mode - Mocking fixture element', () => {

        beforeEach(() => {
            fixture = TestBed.createComponent(ViewerComponent);
            element = fixture.nativeElement;
            component = fixture.componentInstance;

            component.showToolbar = true;
            component.urlFile = 'fake-test-file.pdf';
            component.mimeType = 'application/pdf';
            fixture.detectChanges();
        });

        it('should request only if enabled', () => {
            const domElement = jasmine.createSpyObj('el', ['requestFullscreen']);
            spyOn(fixture.nativeElement, 'querySelector').and.returnValue(domElement);

            component.allowFullScreen = false;
            component.enterFullScreen();

            expect(domElement.requestFullscreen).not.toHaveBeenCalled();
        });

        it('should use standard mode', () => {
            const domElement = jasmine.createSpyObj('el', ['requestFullscreen']);
            spyOn(fixture.nativeElement, 'querySelector').and.returnValue(domElement);

            component.enterFullScreen();
            expect(domElement.requestFullscreen).toHaveBeenCalled();
        });

        it('should use webkit prefix', () => {
            const domElement = jasmine.createSpyObj('el', ['webkitRequestFullscreen']);
            spyOn(fixture.nativeElement, 'querySelector').and.returnValue(domElement);

            component.enterFullScreen();
            expect(domElement.webkitRequestFullscreen).toHaveBeenCalled();
        });

        it('should use moz prefix', () => {
            const domElement = jasmine.createSpyObj('el', ['mozRequestFullScreen']);
            spyOn(fixture.nativeElement, 'querySelector').and.returnValue(domElement);

            component.enterFullScreen();
            expect(domElement.mozRequestFullScreen).toHaveBeenCalled();
        });

        it('should use ms prefix', () => {
            const domElement = jasmine.createSpyObj('el', ['msRequestFullscreen']);
            spyOn(fixture.nativeElement, 'querySelector').and.returnValue(domElement);

            component.enterFullScreen();
            expect(domElement.msRequestFullscreen).toHaveBeenCalled();
        });
    });
});
