/*******************************************************************************
 * MIT License
 *
 * Copyright (c) 2018 Leonardo Gates
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

/**
 * @desc Simple file to spoof Discord's user agent, proxy all connections over Tor & apply some tracking-prevention.
 *      Save This File As:
 *          < discord_desktop_core >/app/secureDiscord.js
 *
 *      Edit The File:
 *          < discord_desktop_core >/app/mainScreen.js
 *
 *          Below Line:
 *              require( './discordCryptLoader.js' )( mainWindow );
 *
 *          If BetterDiscord Is Installed, Before:
 *              _betterDiscord2 = new _betterDiscord.BetterDiscord(mainWindow);
 *
 *          As:
 *              require( './secureDiscord.js' )( mainWindow );
 * @param {BrowserWindow} mainWnd Main BrowserWindow object created upon Discord's main loading event.
 */
module.exports = ( mainWnd ) => {
    let _mainWnd = mainWnd, reloadFlag = false, hookedDom = false;

    const execJS = ( s ) => _mainWnd.webContents.executeJavaScript( s ),
        logColor = 'color: #00007f; font-weight: bold; text-shadow: 0 0 1px #f00, 0 0 2px #0f0, 0 0 3px #00f;',
        log = ( s ) => execJS( `console.log( '%c[SecureDiscord]%c - ${s}', '${logColor}', '' );` ),
        targetURLs = [
            '*://*.*/*',
            '*://*/*',
            '*://*',
            '*'
        ],
        tor_user_agent = 'Mozilla/5.0 (Windows NT 6.1; rv:31.0) Gecko/20100101 Firefox/31.0';

    let domLoad = () => {
        log( 'Initializing ...' );

        hookedDom = true;

        if( reloadFlag ) {
            log( 'Detected a reload.' );
            return;
        }

        reloadFlag = true;

        log( `Setting user agent to: "${tor_user_agent}"` );
        _mainWnd.webContents.setUserAgent( tor_user_agent );

        /* Events in case these every get replaced by any future code. */
        let session = _mainWnd.webContents.session,
            applyHeaders = ( details ) => {
                for( let i in details.requestHeaders ) {
                    if( i.toLowerCase() === 'user-agent' ) {
                        if( details.requestHeaders[ i ] !== tor_user_agent )
                            details.requestHeaders[ i ] = tor_user_agent;
                    }
                }
                details.requestHeaders[ 'DNT' ] = '1';
                details.requestHeaders[ 'Upgrade-Insecure-Requests' ] = '1';
            };
        session.webRequest.onBeforeSendHeaders( [ targetURLs ], ( details, callback ) => {
            applyHeaders( details );
            callback( { cancel: false, requestHeaders: details.requestHeaders } );
        } );
        session.webRequest.onSendHeaders( [ targetURLs ], applyHeaders );

        /* Set the proxy to Tor, fallback to direct connections. */
        log( 'Applying Tor proxy for address 127.0.0.1:9050' );
        session.setProxy(
            { proxyRules: 'socks5://127.0.0.1:9050,direct' },
            () => log( 'Now routing all connections over Tor!' )
        );

        /* Block specific tracking URLs. */
        log( 'Blocking known tracking URLs' );
        session.webRequest.onBeforeRequest( [ targetURLs ], ( details, callback ) => {
            const _defaultHosts = [
                'sentry.io',
                'crash.discordapp.com',
                'discordapp.com/api/science',
                'discordapp.com/api/v6/science',
                'discordapp.com/api/v6/experiments'
            ];

            /* Use the default block list. */
            let filtered = _defaultHosts.filter( e => details.url.indexOf( e ) !== -1 ).length > 0;
            callback( { cancel: filtered } );

            if( filtered )
                log( `[x] ${details.url}` );
        } );
    };

    try {
        _mainWnd.webContents.on( 'dom-ready', domLoad );
        _mainWnd.webContents.on( 'did-finish-loading', () => {
            hookedDom ? domLoad() : null;
        } );
    }
    catch( e ) {
        log( `Exception occurred: ${e}` );
    }
};
