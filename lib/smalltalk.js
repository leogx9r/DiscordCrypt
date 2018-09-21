/**
 The MIT License (MIT)

 Copyright (c) 2015-2018 coderaiser

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
 */

(function() {
    'use strict';

    const BUTTON_OK = [ 'OK' ];
    const BUTTON_OK_CANCEL = [ 'OK', 'Cancel' ];

    const __smalltalk_remove = __smalltalk_bind( __smalltalk_removeEl, '.smalltalk' );

    const __smalltalk_store = ( value ) => {
        const data = {
            value
        };

        return function ( value ) {
            if ( !arguments.length )
                return data.value;

            data.value = value;

            return value;
        };
    };

    function _alert( title, msg, options ) {
        let btn = options && options.button || BUTTON_OK;
        return __smalltalk_showDialog( title, msg, '', btn, { cancel: false } );
    }

    function _prompt( title, msg, value = '', options ) {
        const type = __smalltalk_getType( options );
        const btn = options && options.button || BUTTON_OK_CANCEL;

        const val = String( value )
            .replace( /"/g, '&quot;' );

        const valueStr = `<input type="${ type }" value="${ val }" data-name="js-input">`;

        return __smalltalk_showDialog( title, msg, valueStr, btn, options );
    }

    function _confirm( title, msg, options ) {
        let { buttons } = options && options.button || BUTTON_OK_CANCEL;
        return __smalltalk_showDialog( title, msg, '', buttons, options );
    }

    function __smalltalk_getType( options = {} ) {
        const { type } = options;

        if ( type === 'password' )
            return 'password';

        return 'text';
    }

    function __smalltalk_getTemplate( title, msg, value, buttons ) {
        const encodedMsg = msg.replace( /\n/g, '<br>' );
        return `<div class="page"><div data-name="js-close" class="close-button"></div><header>${ title }</header><div class="content-area">${ encodedMsg }${ value }</div><div class="action-area"><div class="button-strip"> ${buttons.map( ( name, i ) =>`<button tabindex=${ i } data-name="js-${ name.toLowerCase() }">${ name }</button>`).join( '' )}</div></div></div>`;
    }

    function __smalltalk_showDialog( title, msg, value, buttons, options ) {
        const ok = __smalltalk_store();
        const cancel = __smalltalk_store();

        const dialog = document.createElement( 'div' );
        const closeButtons = [
            'cancel',
            'close',
            'ok'
        ];

        const promise = new Promise( ( resolve, reject ) => {
            const noCancel = options && !options.cancel;
            const empty = () => {
            };

            ok( resolve );
            cancel( noCancel ? empty : reject );
        } );

        dialog.innerHTML = __smalltalk_getTemplate( title, msg, value, buttons );
        dialog.className = 'smalltalk';

        document.body.appendChild( dialog );

        __smalltalk_find( dialog, [ 'ok', 'input' ] ).forEach( ( el ) =>
            el.focus()
        );

        __smalltalk_find( dialog, [ 'input' ] ).forEach( ( el ) => {
            el.setSelectionRange( 0, value.length );
        } );

        __smalltalk_addListenerAll( 'click', dialog, closeButtons, ( event ) =>
            __smalltalk_closeDialog( event.target, dialog, ok(), cancel() )
        );

        [ 'click', 'contextmenu' ].forEach( ( event ) =>
            dialog.addEventListener( event, () =>
                __smalltalk_find( dialog, [ 'ok', 'input' ] ).forEach( ( el ) =>
                    el.focus()
                )
            )
        );

        dialog.addEventListener( 'keydown', currify( __smalltalk_keyDownEvent )( dialog, ok(), cancel() ) );

        return promise;
    }

    function __smalltalk_keyDownEvent( dialog, ok, cancel, event ) {
        const KEY = {
            ENTER: 13,
            ESC: 27,
            TAB: 9,
            LEFT: 37,
            UP: 38,
            RIGHT: 39,
            DOWN: 40
        };

        const keyCode = event.keyCode;
        const el = event.target;

        const namesAll = [ 'ok', 'cancel', 'input' ];
        const names = __smalltalk_find( dialog, namesAll )
            .map( __smalltalk_getDataName );

        switch ( keyCode ) {
            case KEY.ENTER:
                __smalltalk_closeDialog( el, dialog, ok, cancel );
                event.preventDefault();
                break;

            case KEY.ESC:
                __smalltalk_remove();
                cancel();
                break;

            case KEY.TAB:
                if ( event.shiftKey )
                    __smalltalk_tab( dialog, names );

                __smalltalk_tab( dialog, names );
                event.preventDefault();
                break;

            default:
                [ 'left', 'right', 'up', 'down' ].filter( ( name ) => {
                    return keyCode === KEY[ name.toUpperCase() ];
                } ).forEach( () => {
                    __smalltalk_changeButtonFocus( dialog, names );
                } );

                break;
        }

        event.stopPropagation();
    }

    function __smalltalk_getDataName( el ) {
        return el
            .getAttribute( 'data-name' )
            .replace( 'js-', '' );
    }

    function __smalltalk_changeButtonFocus( dialog, names ) {
        const active = document.activeElement;
        const activeName = __smalltalk_getDataName( active );
        const isButton = /ok|cancel/.test( activeName );
        const count = names.length - 1;
        const getName = ( activeName ) => {
            if ( activeName === 'cancel' )
                return 'ok';

            return 'cancel';
        };

        if ( activeName === 'input' || !count || !isButton )
            return;

        const name = getName( activeName );

        __smalltalk_find( dialog, [ name ] ).forEach( ( el ) => {
            el.focus();
        } );
    }

    const __smalltalk_getIndex = ( count, index ) => {
        if ( index === count )
            return 0;

        return index + 1;
    };

    function __smalltalk_tab( dialog, names ) {
        const active = document.activeElement;
        const activeName = __smalltalk_getDataName( active );
        const count = names.length - 1;

        const activeIndex = names.indexOf( activeName );
        const index = __smalltalk_getIndex( count, activeIndex );

        const name = names[ index ];

        __smalltalk_find( dialog, [ name ] ).forEach( ( el ) =>
            el.focus()
        );
    }

    function __smalltalk_closeDialog( el, dialog, ok, cancel ) {
        const name = el
            .getAttribute( 'data-name' )
            .replace( 'js-', '' );

        if ( /close|cancel/.test( name ) ) {
            cancel();
            __smalltalk_remove();
            return;
        }

        const value = __smalltalk_find( dialog, [ 'input' ] )
            .reduce( ( value, el ) => el.value, null );

        ok( value );
        __smalltalk_remove();
    }

    function __smalltalk_find( element, names ) {
        return names.map( ( name ) =>
            element.querySelector( `[data-name="js-${ name }"]` )
        ).filter( ( a ) => a );
    }

    function __smalltalk_addListenerAll( event, parent, elements, fn ) {
        __smalltalk_find( parent, elements )
            .forEach( ( el ) =>
                el.addEventListener( event, fn )
            );
    }

    function __smalltalk_removeEl( name ) {
        const el = document.querySelector( name );

        el.parentElement.removeChild( el );
    }

    function __smalltalk_bind( fn, ... args ) {
        return () => fn( ... args );
    }

    $( 'head' ).append(
`<style>
.smalltalk{
    display: flex;
    align-items: center;
    flex-direction: column;
    justify-content: center;
    transition: 200ms opacity;
    bottom: 0;
    left: 0;
    overflow: auto;
    padding: 20px;
    position: fixed;
    right: 0;
    top: 0;
    z-index: 10000
}
.smalltalk + .smalltalk{
    transition: ease 1s;
    display: none
}
.smalltalk .page{
    border-radius: 3px;
    background: #1e2124;
    box-shadow: 0 4px 23px 5px rgba(0, 0, 0, .2), 0 2px 6px rgba(0, 0, 0, .15);
    color: #fff;
    min-width: 400px;
    padding: 0;
    position: relative;
    z-index: 0
}
@media only screen and (max-width: 500px){
    .smalltalk .page{
        min-width: 0
    }
}
.smalltalk .page > .close-button{
    background: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAQAAAC1QeVaAAAAUklEQVR4XqXPYQrAIAhAYW/gXd8NJxTopVqsGEhtf+L9/ERU2k/HSMFQpKcYJeNFI9Be0LCMij8cYyjj5EHIivGBkwLfrbX3IF8PqumVmnDpEG+eDsKibPG2JwAAAABJRU5ErkJggg==') no-repeat center;
    height: 14px;
    position: absolute;
    right: 7px;
    top: 7px;
    width: 14px;
    z-index: 1
}
.smalltalk .page > .close-button:hover{
    background-image:url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAQAAAC1QeVaAAAAnUlEQVR4XoWQQQ6CQAxFewjkJkMCyXgJPMk7AiYczyBeZEAX6AKctGIaN+bt+trk9wtGQc/IkhnoKGxqqiWxOSZalapWFZ6VrIUDExsN0a5JRBq9LoVOR0eEQMoEhKizXhhsn0p1sCWVo7CwOf1RytPL8CPvwuBUoHL6ugeK30CVD1TqK7V/hdpe+VNChhOzV8xWny/+xosHF8578W/Hmc1OOC3wmwAAAABJRU5ErkJggg==')
}
.smalltalk .page header{
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 500px;
    user-select: none;
    color: #fff;
    font-size: 120%;
    font-weight: bold;
    margin: 0;
    padding: 14px 17px;
    text-shadow: #1e2124 0 1px 2px
}
.smalltalk .page .content-area{
    overflow: hidden;
    text-overflow: ellipsis;
    padding: 6px 17px;
    position: relative
}
.smalltalk .page .action-area{
    padding: 14px 17px
}
button{
    font-family: Ubuntu, Arial, sans-serif
}
.smalltalk .smalltalk,.smalltalk button{
    min-height: 2em;
    min-width: 4em
}
.smalltalk button{
    user-select: none;
    background: #36393f;
    border: 1px solid rgba(0, 0, 0, 0.25);
    border-radius: 5px;
    box-shadow: 0 1px 0 rgba(0, 0, 0, 0.08), inset 0 1px 2px #4f545c;
    color: #f0f0f0;
    font: inherit;
    margin: 0 1px 0 0;
    text-shadow: 0 1px 0 #fff
}
.smalltalk button::-moz-focus-inner{
    border: 0
}
.smalltalk button:enabled:active{
    background: #4b4f57;
    color: #fff;
    box-shadow: none;
    text-shadow: none
}
.smalltalk .page .button-strip{
    display: flex;
    flex-direction: row;
    justify-content: flex-end
}
.smalltalk .page .button-strip > button{
    margin-left: 10px
}
.smalltalk input{
    width: 100%;
    border: 1px solid #bfbfbf;
    border-radius: 2px;
    box-sizing: border-box;
    color: #fff;
    background: transparent;;
    font: inherit;
    margin: 0;
    min-height: 2em;
    padding: 3px;
    outline: none
}
.smalltalk button:enabled:focus,.smalltalk input:enabled:focus{
    transition: border-color 200ms;
    border-color: rgb(77, 144, 254);
    outline: none
}
</style>`
    );

    global.smalltalk  = {
        alert: _alert,
        prompt: _prompt,
        confirm: _confirm
    };

    Object.freeze( global.smalltalk );
})();
