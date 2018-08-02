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

    /**
     * @desc Log color CSS defined for logging messages.
     * @type {string}
     */
    const
        logColor = 'color: #00007f; font-weight: bold; text-shadow: 0 0 1px #f00, 0 0 2px #0f0, 0 0 3px #00f;',
        /**
         * @desc Log color CSS for logging filtered URL requests.
         * @type {string}
         */
        warnColor = 'color: #f00; font-weight: bold',
        /**
         * Array of URLs to filter connections from.
         * @type {string[]}
         */
        targetURLs = [
            '*://*.*/*',
            '*://*/*',
            '*://*',
            '*'
        ],
        /**
         * @desc Header information to modify or remove from requests.
         * @type {{modify: Object, remove: string[]}}
         */
        headerInfo = {
            modify: {
                'user-agent': 'Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0',
                'accept-language': 'en-US,en;q=0.5',
                'accept-encoding': 'gzip, deflate, br'
            },
            remove: [
                'x-fingerprint',
                'x-super-properties'
            ]
        },
        /**
         * @desc Specific domain names and paths to block access to.
         * @type {string[]}
         */
        filteredHosts = [
            'sentry.io',
            'crash.discordapp.com',
            'discordapp.com/api/science',
            'discordapp.com/api/v6/science',
            'discordapp.com/api/v6/experiments',
            'webrtc.org/experiments'
        ];

    /**
     * @desc Executes javascript code in the main window.
     * @param code
     * @return {*}
     */
    const execJS = ( code ) => _mainWnd.webContents.executeJavaScript( code );

    /**
     * @desc Executes a console logging operation.
     * @param {string} str The output to the console.
     * @return {*}
     */
    const log = ( str ) => execJS( `console.log( '%c[SecureDiscord]%c ${str}', '${logColor}', '' );` );

    /**
     * @desc Modifies or removes any particular headers according to the `headerInfo` defined above.
     * @param {Object} request Request information defined by the Electron spec.
     * @see https://electronjs.org/docs/api/web-request
     */
    const modifyHeaders = ( request ) => {
        for( let i in request.requestHeaders ) {
            let v = headerInfo.modify[ i.toLowerCase() ];
            if( v && request.requestHeaders[ i ] !== v )
                request.requestHeaders[ i ] = v;
            else if( headerInfo.remove.indexOf( i.toLowerCase() ) !== -1 )
                delete request.requestHeaders[ i ];
        }
    };

    /**
     * @desc Event that executes upon the DOM having finished construction.
     *      This sets up the necessary hooks required.
     */
    const onDomReady = () => {
        log( 'Initializing ...' );

        hookedDom = true;

        if( reloadFlag ) {
            log( 'Detected a reload.' );
            return;
        }

        reloadFlag = true;

        log( 'Setting up header patching.' );
        _mainWnd.webContents.setUserAgent( headerInfo.modify[ 'user-agent' ] );

        /* Events in case these every get replaced by any future code. */
        _mainWnd.webContents.session.webRequest.onBeforeSendHeaders( [ targetURLs ], ( details, callback ) => {
            modifyHeaders( details );
            callback( { cancel: false, requestHeaders: details.requestHeaders } );
        } );
        _mainWnd.webContents.session.webRequest.onSendHeaders( [ targetURLs ], modifyHeaders );

        /* Set the proxy to SOCKS5, fallback to direct connections. */
        log( 'Applying SOCKS5 Proxy: 127.0.0.1:9050' );
        _mainWnd.webContents.session.setProxy(
            { proxyRules: 'socks5://127.0.0.1:9050,direct' },
            () => log( 'Now routing all connections over Tor!' )
        );

        /* Block specific tracking URLs. */
        log( 'Blocking known tracking URLs' );
        _mainWnd.webContents.session.webRequest.onBeforeRequest( [ targetURLs ], ( details, callback ) => {
            /* Use the default block list. */
            let filtered = filteredHosts.filter( e => details.url.indexOf( e ) !== -1 ).length > 0;
            callback( { cancel: filtered } );

            if( filtered )
                execJS(
                    `console.log( '%c[SecureDiscord]%c [%c✖%c] ${details.url}', '${logColor}', '', '${warnColor}', '' )`
                );
        } );
    };

    try {
        /* Apply the DOM hooks. */
        _mainWnd.webContents.on( 'dom-ready', onDomReady );
        _mainWnd.webContents.on( 'did-finish-loading', () => {
            hookedDom ? onDomReady() : null;
        } );
    }
    catch( e ) {
        log( `Exception occurred: ${e}` );
    }
};
