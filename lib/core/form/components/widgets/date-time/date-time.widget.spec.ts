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

import { ComponentFixture, TestBed } from '@angular/core/testing';
import moment from 'moment-es6';
import { FormFieldModel } from './../core/form-field.model';
import { FormModel } from './../core/form.model';
import { DateTimeWidgetComponent } from './date-time.widget';
import { setupTestBed } from '../../../../testing/setup-test-bed';
import { CoreTestingModule } from '../../../../testing/core.testing.module';
import { TranslateModule } from '@ngx-translate/core';
import { MatTooltipModule } from '@angular/material/tooltip';

describe('DateTimeWidgetComponent', () => {

    let widget: DateTimeWidgetComponent;
    let fixture: ComponentFixture<DateTimeWidgetComponent>;
    let element: HTMLElement;

    setupTestBed({
        imports: [
            TranslateModule.forRoot(),
            CoreTestingModule,
            MatTooltipModule
        ]
    });

    beforeEach(() => {
        fixture = TestBed.createComponent(DateTimeWidgetComponent);

        element = fixture.nativeElement;
        widget = fixture.componentInstance;
    });

    afterEach(() => {
        fixture.destroy();
        TestBed.resetTestingModule();
    });

    it('should setup min value for date picker', () => {
        const minValue = '1982-03-13T10:00:000Z';
        widget.field = new FormFieldModel(null, {
            id: 'date-id',
            name: 'date-name',
            type: 'datetime',
            minValue: minValue
        });

        fixture.detectChanges();

        const expected = moment(minValue, 'YYYY-MM-DDTHH:mm:ssZ');
        expect(widget.minDate.isSame(expected)).toBeTruthy();
    });

    it('should date field be present', () => {
        widget.field = new FormFieldModel(null, {
            id: 'date-id',
            name: 'date-name',
            type: 'datetime'
        });
        fixture.detectChanges();

        expect(element.querySelector('#data-time-widget')).toBeDefined();
        expect(element.querySelector('#data-time-widget')).not.toBeNull();
    });

    it('should setup max value for date picker', () => {
        const maxValue = '1982-03-13T10:00:000Z';
        widget.field = new FormFieldModel(null, {
            maxValue: maxValue
        });
        fixture.detectChanges();

        const expected = moment(maxValue, 'YYYY-MM-DDTHH:mm:ssZ');
        expect(widget.maxDate.isSame(expected)).toBeTruthy();
    });

    it('should eval visibility on date changed', () => {
        spyOn(widget, 'onFieldChanged').and.callThrough();

        const field = new FormFieldModel(new FormModel(), {
            id: 'date-field-id',
            name: 'date-name',
            value: '09-12-9999 10:00 AM',
            type: 'datetime',
            readOnly: 'false'
        });

        widget.field = field;

        widget.onDateChanged(moment('1982-03-13T10:00:000Z'));
        expect(widget.onFieldChanged).toHaveBeenCalledWith(field);
    });

    describe('template check', () => {

        it('should show visible date widget', async () => {
            widget.field = new FormFieldModel(new FormModel(), {
                id: 'date-field-id',
                name: 'date-name',
                value: '30-11-9999 10:30 AM',
                type: 'datetime',
                readOnly: 'false'
            });

            fixture.detectChanges();
            await fixture.whenStable();

            expect(element.querySelector('#date-field-id')).toBeDefined();
            expect(element.querySelector('#date-field-id')).not.toBeNull();
            const dateElement: any = element.querySelector('#date-field-id');
            expect(dateElement.value).toBe('30-11-9999 10:30 AM');
        });

        it('should show the correct format type', async () => {
            widget.field = new FormFieldModel(new FormModel(), {
                id: 'date-field-id',
                name: 'date-name',
                value: '12-30-9999 10:30 AM',
                dateDisplayFormat: 'MM-DD-YYYY HH:mm A',
                type: 'datetime',
                readOnly: 'false'
            });

            fixture.detectChanges();
            await fixture.whenStable();

            expect(element.querySelector('#date-field-id')).toBeDefined();
            expect(element.querySelector('#date-field-id')).not.toBeNull();
            const dateElement: any = element.querySelector('#date-field-id');
            expect(dateElement.value).toContain('12-30-9999 10:30 AM');
        });

        it('should disable date button when is readonly', async () => {
            widget.field = new FormFieldModel(new FormModel(), {
                id: 'date-field-id',
                name: 'date-name',
                value: '12-30-9999 10:30 AM',
                dateDisplayFormat: 'MM-DD-YYYY HH:mm A',
                type: 'datetime',
                readOnly: 'false'
            });
            fixture.detectChanges();
            await fixture.whenStable();

            let dateButton = <HTMLButtonElement> element.querySelector('button');
            expect(dateButton.disabled).toBeFalsy();

            widget.field.readOnly = true;
            fixture.detectChanges();
            await fixture.whenStable();

            dateButton = <HTMLButtonElement> element.querySelector('button');
            expect(dateButton.disabled).toBeTruthy();
        });

        it('should display tooltip when tooltip is set', async () => {
            widget.field = new FormFieldModel(new FormModel(), {
                id: 'date-field-id',
                name: 'date-name',
                value: '12-30-9999 10:30 AM',
                dateDisplayFormat: 'MM-DD-YYYY HH:mm A',
                type: 'datetime',
                readOnly: 'false',
                tooltip: 'datetime widget'
            });

            fixture.detectChanges();
            await fixture.whenStable();

            const dateElement: any = element.querySelector('#date-field-id');
            const tooltip = dateElement.getAttribute('ng-reflect-message');

            expect(tooltip).toEqual(widget.field.tooltip);
        });
    });

    it('should display always the json value', () => {
        const field = new FormFieldModel(new FormModel(), {
            id: 'date-field-id',
            name: 'datetime-field-name',
            value: '12-30-9999 10:30 AM',
            type: 'datetime',
            readOnly: 'false'
        });
        field.isVisible = true;
        field.dateDisplayFormat = 'MM-DD-YYYY HH:mm A';
        widget.field = field;
        widget.ngOnInit();
        fixture.detectChanges();
        fixture.whenStable()
            .then(() => {
                expect(element.querySelector('#date-field-id')).toBeDefined();
                expect(element.querySelector('#date-field-id')).not.toBeNull();
                const dateElement: any = element.querySelector('#date-field-id');
                expect(dateElement.value).toContain('12-30-9999 10:30 AM');

                widget.field.value = '03-02-2020 12:00 AM';

                fixture.whenStable()
                    .then(() => {
                        expect(dateElement.value).toContain('03-02-2020 12:00 AM');
                    });
            });
    });
});
