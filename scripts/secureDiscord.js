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
 * @typedef {Object} MainWindowOptions
 * @property {string} title
 * @property {null} backgroundColor
 * @property {number} width
 * @property {number} height
 * @property {number} minWidth
 * @property {number} minHeight
 * @property {boolean} transparent
 * @property {boolean} frame
 * @property {boolean} resizable
 * @property {boolean} show
 * @property {{blinkFeatures: string, preload: string}} webPreferences
 */

/**
 * @desc Enhance Discord's desktop app for privacy.
 *      Usage:
 *
 *
 *      1.) Save This File As:
 *          < discord_desktop_core >/app/secureDiscord.js
 *
 *      2.) Edit The File:
 *          < discord_desktop_core >/app/mainScreen.js
 *
 *          Instead Of Line:
 *              mainWindow = new _electron.BrowserWindow(mainWindowOptions);
 *
 *          Replace With:
 *              mainWindow = require( './secureDiscord.js' )( mainWindowOptions );
 *
 *     3.) Configure the options below to change functionality of the plugin.
 *
 *     Features:
 *          - Blocks various tracking and ad URLs via a subscription list.
 *          - Sets your user agent to Tor's.
 *          - Sets additional HTTP headers to Tor defaults.
 *          - Routes all traffic over Tor ( Requires Tor to be running on 127.0.0.1:9050 )
 *          - Blocks access to known Discord tracking URLs.
 *          - Adds additional block lists.
 *          - Adds Do-Not-Track & Upgrade-Insecure-Requests headers.
 *          - Removes Discord tracking from any external URL.
 *          - Removes several fingerprint based headers from requests.
 *          - Logs all interactions that occurs.
 *
 *
 * @param {MainWindowOptions} mainWindowOptions Main BrowserWindow object created upon Discord's main loading event.
 */
module.exports = ( mainWindowOptions ) => {
    /**
     * @desc Configure your options here.
     */
    const options = {
        /**
         * @desc Whether to spoof HTTP headers sent in requests to those defined below in headerInfo.
         * @type {boolean}
         */
        spoofHeaders: true,
        /**
         * @desc Whether to remove tracking URLs by Discord. This specific path can be configured below in trackingPath.
         * @type {boolean}
         */
        removeTrackingURLs: true,
        /**
         * @desc Whether to use additional HOSTS based block lists defined below.
         */
        useAdditionalBlockList: true,
        /**
         * @desc Whether to tunnel Discord's connections over a proxy.
         * @type {boolean}
         */
        useProxy: true,
        /**
         * @desc When using a proxy, if this is enabled and a connection fails, a direct connection will be used.
         *      If not, the connection is aborted.
         * @type {boolean}
         */
        fallbackToDirectConnection: false,
        /**
         * @desc Whether to enable developer tools and avoid clearing console logs upon startup.
         *      Useful for verifying the script works.
         * @type {boolean}
         */
        debug: false,
        /**
         * @desc Whether to be verbose in logging events that occurred.
         * @type {boolean}
         */
        verbose: false,
        /**
         * @desc If useProxy is enabled, this specifies the proxy address to use for connections.
         *      N.B. This must specify the protocol of the address. Example: "socks5://"
         * @type {string}
         */
        proxyAddress: 'socks5://127.0.0.1:9050',
        /**
         * Array of URLs to capture connections from.
         *      This is a lazy interpretation to be sure to capture all connections.
         *      Don't change this if you don't know what you're doing.
         * @type {string[]}
         */
        targetURLs: [
            '*://*.*/*',
            '*://*/*',
            '*://*',
            '*'
        ],
        /**
         * @desc Log color CSS defined for logging messages.
         * @type {string}
         */
        logColor: 'color: #00007f; font-weight: bold; text-shadow: 0 0 1px #f00, 0 0 2px #0f0, 0 0 3px #00f;',
        /**
         * @desc Log color CSS for logging filtered URL requests.
         * @type {string}
         */
        warnColor: 'color: #f00; font-weight: bold',
        /**
         * @desc Header information to modify or remove from requests.
         *      N.B. These must ALL be lowercase with the exception of headerInfo.insert.
         * @type {{insert: Object, modify: Object, remove: string[]}}
         */
        headerInfo: {
            /* Headers to add to every request. */
            insert: {
                /* @see https://en.wikipedia.org/wiki/Do_Not_Track */
                'DNT': '1',
                /* @see https://www.w3.org/TR/upgrade-insecure-requests */
                'Upgrade-Insecure-Requests': '1'
            },
            /* Headers to modify if they're present in a request. */
            modify: {
                /* Tor Specific Headers */
                'user-agent': 'Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0',
                'accept-language': 'en-US,en;q=0.5',
                'accept-encoding': 'gzip, deflate, br'
            },
            /* Headers to remove if they're present in a request. */
            remove: [
                'via',
                'referer',
                'if-none-match',
                'x-debug',
                'x-track',
                'x-rpc-proxy',
                'x-fingerprint',
                'x-debug-options',
                'x-forwarded-for',
                'x-failed-requests',
                'x-super-properties',
                'x-context-properties',
            ]
        },
        /**
         * @desc Permissions specifically disabled by default.
         * @see https://developer.chrome.com/extensions/permission_warnings
         * @type {string[]}
         */
        disabledWebPermissions: [
            'bookmarks',
            'geolocation',
            'management',
            'notifications',
            'pageCapture',
            'privacy',
            'proxy',
            'system.storage',
            'tabCapture',
            'topSites',
            'webNavigation',
        ],
        /**
         * @desc Direct links to HOSTS file block list for filtering bad URLs.
         * @type {string[]}
         */
        blockListURLs: [
            /* Dan Pollock's Hosts File. */
            'https://someonewhocares.org/hosts/hosts',
            /* HpHosts Ad & Tracker List. */
            'https://hosts-file.net/ad_servers.txt',
            /* Peter Lowe’s Ad & Tracking Server List. */
            'https://pgl.yoyo.org/adservers/serverlist.php?showintro=0;hostformat=hosts',
        ],
        /**
         * @desc Specific domain names and paths to block access to.
         *      Can be used as a form of Ad-Blocking.
         * @type {string[]}
         */
        filteredHosts: [
            /* Crash and error reporting URLs. */
            'sentry.io',
            'crash.discordapp.com',

            /* User event tracking. ( Example: When you open menus/channels. ) */
            'discordapp.com/api/science',
            'discordapp.com/api/v6/science',
            /* Old URLs they may eventually switch back to. */
            'discordapp.com/api/track',
            'discordapp.com/api/v6/track',
            /* Potential future URLs when Discord upgrades their API. */
            'discordapp.com/api/v7/science',
            'discordapp.com/api/v7/track',

            /* Various experiments that Discord makes the user participate in. */
            'discordapp.com/api/v6/experiments',

            /* Reports the quality of voice connections and other metadata. */
            'discordapp.com/api/v6/rtc/quality-report',

            /* Generic tracking URLs. */
            'google-analytics.com',
            'webrtc.org/experiments'
        ],
        /**
         * @desc Discord modifies any posted URL to add a tracker to it.
         *      This removes that and redirects to the original.
         *      Example:
         *              xxx.discordapp.net/external/< Tracking ID >/https/google.com
         *              -> https://google.com
         * @type {string}
         */
        urlTrackingPath: 'discordapp.net/external/',
    };

    /**
     * @private
     * @desc Built hosts block list.
     * @type {Array<string>}
     */
    let _filteredHosts = [].concat( options.filteredHosts );

    /**
     * @desc Electron module.
     * @type {module:electron}
     */
    const electron = require( 'electron' );

    /* Disable specific permissions. */
    electron.session.defaultSession.setPermissionRequestHandler(
        ( webContents, permission, callback ) => {
            /* If a disabled permission is being used, reject the request. */
            if( options.disabledWebPermissions.indexOf( permission ) !== -1 ) {
                callback( false );
                return;
            }

            /* Allow the permission. */
            callback( true );
        }
    );

    /* Recreate the main window. */
    let mainWnd = new ( electron.BrowserWindow )( mainWindowOptions );

    /**
     * @desc Executes javascript code in the main window.
     * @param {string} code
     */
    const execJS = ( code ) => mainWnd.webContents.executeJavaScript( code );

    /**
     * @desc Executes a console logging operation.
     * @param {string} str The output to the console.
     */
    const log = ( str ) => {
        if( options.verbose )
            execJS( `console.log( '%c[SecureDiscord]%c ${str}', '${options.logColor}', '' );` );
    };

    /**
     * @desc Logs a URL filtered operation.
     * @param {string} path The path that was filtered.
     */
    const logBlockedTracker = ( path ) => {
        if( options.verbose )
            execJS(
                `console.log(
                    '%c[SecureDiscord]%c [%c✖%c] ${path}',
                    '${options.logColor}',
                    '',
                    '${options.warnColor}',
                    ''
                );`
            );
    };

    /**
     * @desc Parses a HOSTS file's raw data and returns all host name URIs in it.
     * @param {string} data The raw string data.
     * @return {string[]}
     */
    const parseHosts = ( data ) => {
        let result = [];

        /* Remove all comments from the data and split into lines. */
        data = data.replace( /#.*/g, '' ).split( /[\r\n]/ );
        for( let i = 0; i < data.length; i++ ) {
            /* Get the middle of the line by filtering the IP address. */
            let md = ( /(\d+\.\d+\.\d+\.\d+)\s+(.+)/ ).exec( data[ i ] );

            /* Skip invalid. */
            if( !md )
                continue;

            /* Skip invalid results. */
            if( md.length !== 3 )
                continue;

            /* Add to the array. */
            result.push( md[ 2 ] )
        }
        return result;
    };

    /**
     * @desc Downloads and adds all HOSTS files if required and builds the full blocking list.
     */
    const buildBlockList = ( ) => {
        /* Skip if not downloading additional hosts. */
        if( !options.useAdditionalBlockList )
            return;

        /* Request each file defined in options. */
        const request = require( 'request' );
        for( let link of options.blockListURLs ) {
            request.get(
                link,
                ( error, response, data ) => {
                    /* Make sure no error occurred. */
                    if( error || response.statusCode !== 200 ) {
                        log( error || `Error downloading file: ${link} - Code ${response.statusCode}` );
                        return;
                    }

                    /* Gather all URLs in the hosts file. */
                    let result = parseHosts( data );

                    /* Add it to the filter list. */
                    if( result.length ) {
                        let oldLength = _filteredHosts.length;

                        /* Filter only the unique entries. */
                        _filteredHosts = _filteredHosts.concat( result ).filter( ( v, i, s ) => s.indexOf( v ) === i );

                        log( `Added ${_filteredHosts.length - oldLength} hosts to block list.` );
                    }
                }
            )
        }
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
            let v = options.headerInfo.modify[ i.toLowerCase() ];
            if( v && request.requestHeaders[ i ] !== v )
                request.requestHeaders[ i ] = v;
            else if( options.headerInfo.remove.indexOf( i.toLowerCase() ) !== -1 )
                delete request.requestHeaders[ i ];
        }

        /* Add any headers needed. */
        for( let i in options.headerInfo.insert ) {
            /* Determine if the header is already present in lowercase form. */
            let _i = request.requestHeaders.hasOwnProperty( i.toLowerCase() ) ? i.toLowerCase() : i;

            /* Skip if it already exists and the value is as expected. */
            if( request.requestHeaders[ _i ] === options.headerInfo.insert[ i ] )
                continue;

            /* Add the header. */
            request.requestHeaders[ _i ] = options.headerInfo.insert[ i ];
        }
    };

    /**
     * @desc Executes all patching necessary.
     */
    try {
        /* Patch the console. */
        if( options.debug ) {
            mainWnd.webContents.executeJavaScript( 'console.clear = () => { };' );
            mainWnd.webContents.toggleDevTools();
        }

        /* Setup the header spoofing if required. */
        if( options.spoofHeaders ) {
            log( 'Setting up header patching.' );
            mainWnd.webContents.setUserAgent( options.headerInfo.modify[ 'user-agent' ] );
            mainWnd.webContents.setUserAgent = () => {
                /* Ignore. */
            };

            mainWnd.webContents.session.webRequest.onBeforeSendHeaders(
                [ options.targetURLs ],
                ( details, callback ) => {
                    modifyHeaders( details );
                    callback( { cancel: false, requestHeaders: details.requestHeaders } );
                }
            );
            mainWnd.webContents.session.webRequest.onSendHeaders( [ options.targetURLs ], modifyHeaders );
        }

        /* Apply the proxy if necessary. */
        if( options.useProxy ) {
            log( 'Applying Proxy ...' );
            mainWnd.webContents.session.setProxy(
                { proxyRules: `${options.proxyAddress}${options.fallbackToDirectConnection ? ',direct' : ''}` },
                () => log( `Now routing all connections to: ${options.proxyAddress}` )
            );
            mainWnd.webContents.session.setProxy = () => {
                /* Ignore. */
            };
        }

        /* Filter tracking URLs if necessary. */
        if( options.removeTrackingURLs ) {
            /* Block specific tracking URLs. */
            log( 'Blocking known tracking URLs' );
            mainWnd.webContents.session.webRequest.onBeforeRequest( [ options.targetURLs ], ( details, callback ) => {
                /* Use the default block list. */
                let filtered = _filteredHosts.filter( e => details.url.indexOf( e ) !== -1 ).length > 0;

                /* Handle link tracking via external URLs if not filtered. */
                let ext_tracking_pos;
                if(
                    !filtered &&
                    ( ext_tracking_pos = details.url.indexOf( options.urlTrackingPath ), ext_tracking_pos !== -1 )
                ) {
                    let part_url = details.url.substr( options.urlTrackingPath.length + ext_tracking_pos );

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
                    logBlockedTracker( details.url );

                callback( { cancel: filtered } );
            } );

            /* Build the block list. */
            buildBlockList();
            log( typeof window );
        }
    }
    catch( e ) {
        log( `Exception occurred: ${e}` );
    }
    return mainWnd;
};

