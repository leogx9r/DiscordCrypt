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
 * @desc Enhance Discord's desktop app for privacy.
 *      Save This File As:
 *          < discord_desktop_core >/app/secureDiscord.js
 *
 *      Edit The File:
 *          < discord_desktop_core >/app/mainScreen.js
 *
 *          Below Line:
 *              mainWindow = new _electron.BrowserWindow(mainWindowOptions);
 *
 *          If BetterDiscord Is Installed, Before:
 *              _betterDiscord2 = new _betterDiscord.BetterDiscord(mainWindow);
 *
 *          As:
 *              require( './secureDiscord.js' )( mainWindow );
 *     Features:
 *          - Sets your user agent to Tor's.
 *          - Sets additional HTTP headers to Tor defaults.
 *          - Routes all traffic over Tor ( Requires Tor to be running on 127.0.0.1:9050 )
 *          - Blocks access to known Discord tracking URLs.
 *          - Adds Do-Not-Track & Upgrade-Insecure-Requests headers.
 *          - Removes tracking from any external URL.
 *          - Removes several fingerprint based headers from requests.
 *
 * @param {BrowserWindow} mainWnd Main BrowserWindow object created upon Discord's main loading event.
 */
module.exports = ( mainWnd ) => {
    /**
     * @desc Generates a random IP address.
     * @return {string}
     */
    const randomIP = () => {
        const pseudoRandomBytes = require( 'crypto' ).pseudoRandomBytes;
        const invalid = [
            0, 10, 100, 127, 169, 172, 192, 198, 203, 224,
            225, 226, 227, 228, 229, 230, 231, 232, 233, 234,
            235, 236, 237, 238, 239, 240, 241, 242, 243, 244,
            245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
            255
        ];

        let buf = new Uint8Array( [ 0, 0, 0, 0 ] );
        let i = 0;

        do {
            buf[ i ] = pseudoRandomBytes( 1 )[ 0 ];
            if( invalid.indexOf( buf[ i ] ) !== -1 )
                continue;
            i++;
        } while( i < 4 );

        return `${buf[ 0 ]}.${buf[ 1 ]}.${buf[ 2 ]}.${buf[ 3 ]}`
    };

    const
        /**
         * @desc Main window created during the Electron load event.
         * @type {BrowserWindow}
         */
        _mainWnd = mainWnd,
        /**
         * @desc Whether to enable developer tools upon startup ( and avoid clearing console logs. )
         * @type {boolean}
         */
        debug = false,
        /**
         * @desc Whether to be verbose in logging.
         * @type {boolean}
         */
        verbose = true,
        /**
         * @desc Log color CSS defined for logging messages.
         * @type {string}
         */
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
         * @type {{insert: Object, modify: Object, remove: string[]}}
         */
        headerInfo = {
            insert: {
                'DNT': '1',
                'Upgrade-Insecure-Requests': 1
            },
            modify: {
                'if-none-match': ( Math.random() * 10 ).toString( 36 ).substr( 2, Math.random() * 11 ),
                'user-agent': 'Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0',
                'accept-language': 'en-US,en;q=0.5',
                'accept-encoding': 'gzip, deflate, br',
                '"x-forwarded-for': randomIP(),
                'via': randomIP(),
            },
            remove: [
                'x-fingerprint',
                'x-debug',
                'x-debug-options',
                'x-failed-requests',
                'x-super-properties',
                'x-context-properties',
                'referer'
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
            'discordapp.com/api/v6/rtc/quality-report',
            'google-analytics.com',
            'webrtc.org/experiments'
        ],
        /**
         * @desc Discord modifies any posted URL to add a tracker to it. This removes that.
         *      Example:
         *              discordapp.net/external/< Tracking ID >/https/google.com
         * @type {string}
         */
        external_tracking_path = 'discordapp.net/external/';

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
    const log = ( str ) => {
        if( verbose )
            execJS( `console.log( '%c[SecureDiscord]%c ${str}', '${logColor}', '' );` );
    };

    /**
     * @desc Modifies, inserts or removes any particular headers according to the `headerInfo` defined above.
     * @param {Object} request Request information defined by the Electron spec.
     * @see https://electronjs.org/docs/api/web-request
     */
    const modifyHeaders = ( request ) => {
        /* Skip encoded data URLs. */
        if( request.url.indexOf( 'data:image/' ) !== -1 )
            return;

        /* Scan headers for removal or modification. */
        for( let i in request.requestHeaders ) {
            let v = headerInfo.modify[ i.toLowerCase() ];
            if( v && request.requestHeaders[ i ] !== v )
                request.requestHeaders[ i ] = v;
            else if( headerInfo.remove.indexOf( i.toLowerCase() ) !== -1 )
                delete request.requestHeaders[ i ];
        }

        /* Add any headers needed. */
        for( let i in headerInfo.insert ) {
            /* Determine if the header is already present in lowercase form. */
            let _i = request.requestHeaders.hasOwnProperty( i.toLowerCase() ) ? i.toLowerCase() : i;

            /* Skip if it already exists and the value is as expected. */
            if( request.requestHeaders[ _i ] === headerInfo.insert[ i ] )
                continue;

            /* Add the header. */
            request.requestHeaders[ _i ] = headerInfo.insert[ i ];
        }
    };

    /**
     * @desc Executes all patching necessary.
     */
    const doPatch = () => {
        log( 'Setting up header patching.' );
        _mainWnd.webContents.setUserAgent( headerInfo.modify[ 'user-agent' ] );
        _mainWnd.webContents.setUserAgent = () => {
            /* Ignore. */
        };

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
        _mainWnd.webContents.session.setProxy = () => {
            /* Ignore. */
        };

        /* Block specific tracking URLs. */
        log( 'Blocking known tracking URLs' );
        _mainWnd.webContents.session.webRequest.onBeforeRequest( [ targetURLs ], ( details, callback ) => {
            /* Use the default block list. */
            let filtered = filteredHosts.filter( e => details.url.indexOf( e ) !== -1 ).length > 0;

            /* Handle link tracking via external URLs if not filtered. */
            let ext_tracking_pos;
            if(
                !filtered &&
                ( ext_tracking_pos = details.url.indexOf( external_tracking_path ), ext_tracking_pos !== -1 )
            ) {
                let part_url = details.url.substr( external_tracking_path.length + ext_tracking_pos );

                /* Scroll past the "/" identifier part. */
                let link_pos = part_url.indexOf( '/' );
                if( link_pos === -1 ) {
                    callback( { cancel: filtered } );
                    return;
                }
                part_url = part_url.substr( link_pos + 1 );

                /* Make sure it begins with the "http" or "https" */
                if( !( part_url.indexOf( 'https' ) === 0 || part_url.indexOf( 'http' ) === 0 ) ) {
                    callback( { cancel: filtered } );
                    return;
                }

                let is_https = !part_url.indexOf( 'https' );

                /* Scroll past the "/" identifier part. */
                link_pos = part_url.indexOf( '/' );
                if( link_pos === -1 ) {
                    callback( { cancel: filtered } );
                    return;
                }
                part_url = part_url.substr( link_pos + 1 );

                /* Build the final URL. */
                let redirectURL = `${is_https ? 'https' : 'http'}://${part_url}`;
                log( `Removed Tracker: ${redirectURL}` );

                /* Do the redirect. */
                callback( {
                    cancel: false,
                    redirectURL: redirectURL
                } );
                return;
            }

            if( filtered )
                execJS(
                    `console.log( '%c[SecureDiscord]%c [%c✖%c] ${details.url}', '${logColor}', '', '${warnColor}', '' )`
                );

            callback( { cancel: filtered } );
        } );
    };

    try {
        if( debug ) {
            _mainWnd.webContents.executeJavaScript( 'console.clear = () => { };' );
            _mainWnd.webContents.toggleDevTools();
        }

        doPatch();
    }
    catch( e ) {
        log( `Exception occurred: ${e}` );
    }
};
