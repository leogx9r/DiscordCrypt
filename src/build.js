const LICENSE =

`/*******************************************************************************
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
 ******************************************************************************/\n\n`;

const INSTALL_SCRIPT_HEAD =

`/*@cc_on
@if (@_jscript)
    var shell = WScript.CreateObject("WScript.Shell");
    var fs = new ActiveXObject("Scripting.FileSystemObject");
    var pathPlugins = shell.ExpandEnvironmentStrings("%APPDATA%\\BetterDiscord\\plugins");
    var pathSelf = WScript.ScriptFullName;
    shell.Popup("It looks like you mistakenly tried to run me directly. (don't do that!)", 0, "I'm a plugin for BetterDiscord", 0x30);
    if (fs.GetParentFolderName(pathSelf) === fs.GetAbsolutePathName(pathPlugins)) {
        shell.Popup("I'm in the correct folder already.\\nJust reload Discord with Ctrl+R.", 0, "I'm already installed", 0x40);
    } else if (!fs.FolderExists(pathPlugins)) {
        shell.Popup("I can't find the BetterDiscord plugins folder.\\nAre you sure it's even installed?", 0, "Can't install myself", 0x10);
    } else if (shell.Popup("Should I copy myself to BetterDiscord's plugins folder for you?", 0, "Do you need some help?", 0x34) === 6) {
        fs.CopyFile(pathSelf, fs.BuildPath(pathPlugins, fs.GetFileName(pathSelf)), true);
        // Show the user where to put plugins in the future
        shell.Exec("explorer " + pathPlugins);
        shell.Popup("I'm installed!\\nJust reload Discord with Ctrl+R.", 0, "Successfully installed", 0x40);
    }
    WScript.Quit();
@else @*/\n\n`;

const INSTALL_SCRIPT_TAIL = `\n\n/*@end @*/\n`;

const METADATA_HEADER = `//META{"name":"discordCrypt"}*//\n\n`;

/**
 * @public
 * @desc Compiles the plugin and adds all necessary _libraries to it.
 */
class Compiler {

    /**
     * @typedef {Object} LibraryInfo
     * @desc Contains the library and necessary information.
     * @property {boolean} requiresNode Whether this library relies on NodeJS internal support.
     * @property {boolean} requiresBrowser Whether this library is meant to be run in a browser.
     * @property {string} code The raw code for execution defined in the library.
     */

    /**
     * @typedef {Object} LibraryDefinition
     * @desc Contains a definition of a raw library executed upon plugin startup.
     * @property {string} name The name of the library file.
     * @property {LibraryInfo} info The library info.
     */

    /**
     * @typedef {Object} ExportKeyCallback
     * @desc Callback function to receive an exported GPG public key.
     * @property {Error|Buffer} If an error occurred, it returns it otherwise returns the raw output.
     */

    /**
     * @public
     * @desc Resolves all necessary modules.
     */
    constructor() {
        /**
         * @desc Cache the FS module for file operations.
         * @type {fs}
         */
        this.fs = require( 'fs' );

        /**
         * @desc Cache the PATH module for constructing relative and absolute paths.
         * @type {path}
         */
        this.path = require( 'path' );

        /**
         * @desc Cache the CHILD_PROCESS module for exporting GPG keys.
         * @type {child_process}
         */
        this.child_process = require( 'child_process' );

        /**
         * @desc Cache the PROCESS module for argument retrieval.
         * @type {process}
         */
        this.process = require( 'process' );

        /**
         * @desc Cache the crypto module wrapper for Ed25519 signature generation.
         */
        this.crypto = require( 'crypto' );

        /**
         * @desc Cache the ZLIB module for compression.
         * @type {zlib}
         */
        this.zlib = require( 'zlib' );

        /**
         * @desc Cache the GPG module wrapper for build signature generation.
         */
        this.gpg = require( 'gpg' );

        /**
         * @desc Cache the Uglify-JS ( ES ) Module for compressing sources.
         */
        this.uglifyjs = require( 'uglify-es' );

        /**
         * @desc Defines the default options applied to _libraries and optionally the main module if enabled.
         * @type {Object}
         */
        this.defaultBuilderOptions = {
            parse: {
                bare_returns: true,
                toplevel: true
            },
            mangle: true,
            compress: {
                ecma: 6,
                toplevel: true,
                dead_code: true,
                unsafe_Function: true,
                unsafe_methods: true,
                unused: true
            },
            output: {
                ascii_only: false,
                beautify: false,
            },
            warnings: false,
        };
    }

    /**
     * @desc Compress the input data using ZLIB and return the Base64 converted output.
     * @param {string} data The input data to compress.
     * @return {string} Returns the Base64 output of the compression operation.
     */
    compress( data ) {
        return this.zlib.deflateSync(
            data,
            {
                level: this.zlib.constants.Z_BEST_COMPRESSION,
                memLevel: this.zlib.constants.Z_BEST_COMPRESSION,
                strategy: this.zlib.constants.Z_DEFAULT_STRATEGY,
                chunkSize: 65536,
                windowBits: 15
            }
        ).toString( 'base64' );
    }

    /**
     * @desc Attempts to compress the specified data via uglify-es.
     * @param {string} data The data to compress.
     * @param {boolean} use_options Whether to use the default mangling options defined in the constructor.
     * @return {string} Returns either the original data on error or the compressed data.
     */
    tryMinify( data, use_options = true ) {
        try {
            let _data = this.uglifyjs.minify( data.toString(), use_options ? this.defaultBuilderOptions : undefined );

            /* Skip on error. */
            if ( _data.error !== undefined )
                throw `${_data.error}`;
            else
                data = _data.code;

            if ( _data.warnings )
                console.warn( _data.warnings );
        }
        catch ( e ) {
            console.warn( `Warning: ${e.toString()} ...\nSkipping compression ...` );
        }
        return data;
    }

    /**
     * @desc Extracts public key for this key ID to a Buffer.
     * @param {string} key_id The key ID to extract.
     * @param {boolean} armored Whether to armor the output key.
     * @param {ExportKeyCallback} callback The callback function to execute after spawning is complete.
     */
    getPublicKey( key_id, armored, callback ) {
        /* Create the GPG process. */
        let gpg = require( 'child_process' ).spawn(
            'gpg',
            armored ? [ '-a', '--export', key_id ] : [ '--export', key_id ]
        );

        /* Create variables to store the output or errors. */
        let error, outputs = [], output_length = 0;

        /* If output is chunked, add it to the total pool and calculate the new length. */
        gpg.stdout.on( 'data', ( buf ) => {
            outputs.push( buf );
            output_length += buf.length;
        } );

        /* Update the error variable. */
        gpg.stderr.on( 'data', ( buf ) => {
            error += buf.toString( 'utf8' );
        } );

        /* Handle the process closing. */
        gpg.on( 'close', ( exit_code ) => {
            let msg = Buffer.concat( outputs, output_length );
            if ( exit_code !== 0 ) {
                // If error is empty, we probably redirected stderr to stdout (for verifySignature, import, etc)
                callback( new Error( error || msg ) );
                return;
            }

            callback( msg );
        } );
    }

    /**
     * @private
     * @desc Reads all library files in the path specified and constructs an array string containing the data.
     * @param {string} library_path Relative path to look for all library files.
     * @param {LibraryDefinition} library_info A list of the info requires to add to a library.
     * @returns {string} Returns a sanitized string containing the library name and the code.
     */
    compileLibraries( library_path = './lib', library_info = {} ) {
        let libs = {};
        let str = '';

        /* Read all files in the specified directory. */
        let files = this.fs.readdirSync( library_path );

        /* Loop over every file index. */
        for ( let i in files ) {
            /* Get the file name. */
            let file = files[ i ];

            /* Make sure this is a javascript file. Not just a .map file. */
            if ( this.path.extname( file ) !== '.js' ) {
                console.info( `Skipping non-javascript file in "${library_path}" - ${file} ...` );
                continue;
            }

            /* Get the base name. */
            let base = this.path.basename( file );

            /* Make sure the base name is defined in the library info. */
            if ( !library_info.hasOwnProperty( base ) ) {
                console.warn( `Skipping non-defined library: "${base}" ...` );
                continue;
            }

            /* Read the file to a buffer. */
            let data = this.fs.readFileSync( this.path.join( library_path, file ) );

            /* Make sure something is returned. */
            if ( !data || !Buffer.isBuffer( data ) ) {
                console.error( `Failed to read library file: ${file} ...` );
                continue;
            }

            /* Try minifying the library if required. */
            if( library_info[ base ].minify )
                data = this.tryMinify( data );

            /* Compress the data to a Base64 buffer and update the code in the library info. */
            library_info[ base ][ 'code' ] = this.compress( data );

            /* Add it to the array. */
            libs[ file ] = library_info[ base ];

            /* Quick log. */
            console.info( `Added library: [ ${base} ] - ${
                parseFloat( library_info[ base ][ 'code' ].length / 1024 ).toFixed( 3 )
            } KB ...` );
        }

        /* Construct a sanitized array string. */
        for ( let id in libs )
            str += `'${id}': ${JSON.stringify( libs[ id ] )},\n            `;

        /* Remove the last comma added by the above loop. */
        str = str.trimRight().slice( 0, str.length - 1 - 1 );

        /* Log the total size. */
        console.info( `======= Total Library Size: ${parseFloat( str.length / 1024 ).toFixed( 3 )} KB =======` );

        /* Return the full string. */
        return str;
    }

    /**
     * @private
     * @desc Reads all asset files in the path specified and replaces them in the base file.
     * @param {string} asset_path The path to the assets directory.
     * @param {string} original_data The original base file data.
     * @param {Object} constants Object containing the tags for each file to replace.
     * @param {string[]} ignore_list Asset names to exclude from stripping line feeds and spaces.
     */
    compileAssets( asset_path = './assets', original_data, constants, ignore_list ) {
        /* Read all files in the specified directory. */
        let files = this.fs.readdirSync( asset_path ), total_length = 0;

        /* Loop over every file index. */
        for ( let i in files ) {
            /* Get the file path and name. */
            let file = files[ i ], file_name = this.path.basename( files[ i ] );

            /* Make sure the tag exists for this file. */
            if ( !constants[ file_name ] ) {
                console.warn( `Unhandled asset file: [ ${file_name} ] ...` );
                continue;
            }

            /* Read the file into a buffer. */
            let data = this.fs.readFileSync( this.path.join( asset_path, file ) ).toString();

            data = data.split( "\r" ).join( "" );

            if( ignore_list.indexOf( file_name ) === -1 )
                data = data.split( "\n" ).join( '' ).split( '    ' ).join( ' ' );

            /* Compress the buffer. */
            data = this.compress( data );
            total_length += data.length;

            /* Replace the data with the compressed result. */
            original_data = original_data
                .split( constants[ file_name ] )
                .join( data );

            /* Quick log. */
            console.info( `Added asset: [ ${this.path.basename( file )} ] - ${
                parseFloat( data.length / 1024 ).toFixed( 3 )
            } KB ...` );
        }

        /* Log the total size. */
        console.info( `======== Total Asset Size: ${parseFloat( total_length / 1024 ).toFixed( 3 )} KB ========` );

        return original_data;
    }


    /**
     * @private
     * @desc Compiles the plugin and adds all necessary _libraries.
     * @param {string} plugin_path The path to the plugin file used as the base.
     * @param {string} tag_name The tag name to scan the [plugin] for to insert all _libraries.
     * @param {string} library_path The path to the _libraries used to add to the base file.
     * @param {LibraryDefinition} library_info Required library info.
     * @param {string} output_dir The output directory to store the plugin.
     * @param {string} assets_path The path to the assets directory.
     * @param {boolean} compress Whether to compress the plugin itself.
     * @param {Object} assets_data The asset tags for each file within the assets directory.
     * @param {string[]} ignore_assets Assets to exclude from compression.
     * @param {string} [sign_key_id] Generates a GPG signature on the output file using this key ID.
     * @return {boolean} Returns true on success and false on failure.
     */
    compilePlugin(
        plugin_path,
        tag_name,
        library_path,
        library_info,
        output_dir,
        assets_path,
        compress,
        assets_data,
        ignore_assets,
        sign_key_id
    ) {
        /* Read the plugin file. */
        let data = this.fs.readFileSync( plugin_path );

        /* Make sure something was read. */
        if ( !data || !Buffer.isBuffer( data ) ) {
            console.error( `Failed to read library file: ${file} ...` );
            return false;
        }

        /* Convert the read data to a string. */
        data = data.toString();

        /* Make sure the tag is present in the file. */
        if ( data.lastIndexOf( tag_name ) === -1 ) {
            console.error( `Failed to locate the tag in the plugin file ...` );
            return false;
        }
        /* Compile all _libraries and replace the tag with them. */
        data = data.split( tag_name ).join( this.compileLibraries( library_path, library_info ) );

        /* Construct the output path and name. */
        let output_path = this.path.join( output_dir, this.path.basename( plugin_path ) );

        /* Create the directory if it doesn't already exist. */
        try {
            this.fs.mkdirSync( output_dir );
        } catch ( e ) {
            /* Ignored. */
        }

        /* Add all assets. */
        data = this.compileAssets( assets_path, data, assets_data, ignore_assets );

        /* Only do this if we're compressing the plugin. */
        if ( compress )
            data = LICENSE + this.tryMinify( data, true );

        /* Build the full file in memory. */
        data = METADATA_HEADER + INSTALL_SCRIPT_HEAD + data + INSTALL_SCRIPT_TAIL;

        try {
            /* Write the file to the output. */
            this.fs.writeFileSync( output_path, data );

            /* For flatpak builds, this needs to be copied as symlinks are forbidden. */
            let FLATPAK_OUTPUT_PATH =
                    this.path.resolve( `${this.process.env.HOME}/.var/app/com.discordapp.Discord/config` ),
                FLATPAK_OUTPUT_FILE = `${FLATPAK_OUTPUT_PATH}/BetterDiscord/plugins/discordCrypt.plugin.js`;
            if(
                this.process.platform === 'linux' &&
                this.fs.existsSync( FLATPAK_OUTPUT_PATH )
            ) {
                this.fs.writeFileSync(
                    FLATPAK_OUTPUT_FILE,
                    METADATA_HEADER + data
                );
                console.info( `Copied Build File: [ ${FLATPAK_OUTPUT_FILE} ] ...` );
            }
        }
        catch ( e ) {
            console.error( `Error building plugin:\n    ${e.toString()}` );
            return false;
        }

        /* Signal to the user. */
        console.info(
            `Destination File: [ ${output_path} ] - ${parseFloat( data.length / 1024 ).toFixed( 3 )} KB ...`
        );

        /* Generate a signature if required. */
        if( sign_key_id ) {
            /* Generating both sets of signatures requires us to load Curve25519. The easiest way is via DiscordCrypt. */
            let { discordCrypt } = require( `../${output_path}` );
            discordCrypt.__loadLibraries();

            let update_signature_file = this.path.join( output_dir, `${this.path.basename( plugin_path )}.sig.bin` );

            /* Load the private key into a new Curve25519 object. */
            let curveKey = new global.Curve25519();
            curveKey.setPrivateKey(
                Buffer.from(
                    this.fs.readFileSync( `${plugin_path}.key` ).toString( 'utf8' ),
                    'base64'
                )
            );

            /* Now we produce a detached 512-bit binary signature using Ed25519. */
            let detachedSignature = curveKey.sign(
                Buffer.from( data ),
                this.crypto.randomBytes( 64 )
            );

            /* Write the signature to the file. */
            this.fs.writeFileSync( update_signature_file, detachedSignature );

            /* Finally log the produced signature. */
            console.log( `Generated Ed25519 Signature: [ ${update_signature_file} ]` );
            console.log( `->    0x${detachedSignature.toString( 'hex' ).toUpperCase()}` );

            /* Generate the GPG signature for manual verification. */
            console.info( `Generating GPG Signature Using Key: [ 0x${sign_key_id} ] ...` );

            /* Generate the GPG signature. */
            let gpg_signature_file = this.path.join( output_dir, `${this.path.basename( plugin_path )}.asc` );
            this.gpg.callStreaming(
                output_path,
                gpg_signature_file,
                [ '-a', '-b', '--default-key', sign_key_id ],
                ( error, result ) => {
                    /* Check if an error occurred and log it. */
                    if ( !error && !result ) {
                        /* Log the result. */
                        console.info( `Generated Detached GPG Signature: [ ${gpg_signature_file} ] ...` );

                        /* Attempt to validate the signature produced. */
                        this.gpg.call(
                            '',
                            [ '--logger-fd', '1', '--verify', gpg_signature_file, output_path ],
                            ( e, r ) => {
                                /* Check if an error occurred and log it. */
                                if ( !e && r && r.length ) {
                                    /* Test the output for the "Good signature" message from GPG. */
                                    let valid = ( new RegExp( /good signature/i ) ).exec( r.toString() ) !== null;

                                    /* Log the appropriate response. */
                                    if ( valid )
                                        console.info(
                                            `\n=============================================\n` +
                                            r.toString() +
                                            `=============================================`
                                        );
                                    else
                                        console.error(
                                            `\n=============================================\n` +
                                            `[ ERROR ] Invalid Signature ...\n${r.toString()}` +
                                            `\n=============================================`
                                        );
                                }
                                else
                                    console.error(
                                        `\n=============================================\n` +
                                        `[ ERROR ] Generating Signature\n    Error: ${e}` +
                                        `\n=============================================`
                                    );
                            }
                        );
                    }
                    else
                        console.error(
                            `\n=============================================\n` +
                            `[ ERROR ] Generating Signature:\n    Error: ${error}\n    Result: ${result}\n` +
                            `\n=============================================`
                        );
                }
            );

            /* Make sure the private key exists. */
            if( !this.fs.existsSync( `${plugin_path}.key` ) ) {
                console.log(
                    'Warning: Could not find the Ed25519 private key to generate an update signature!!!',
                    'warn'
                );
                return true;
            }
        }
        else
            console.info( `=============================================\n` );

        return true;
    }

    /**
     * @public
     * @desc Parses the command line arguments are runs the compiler.
     */
    run() {
        /* Construct the default arguments. */
        const defaults = {
            library_tag:
                '/* ----- LIBRARY DEFINITIONS GO HERE DURING COMPILATION. DO NOT REMOVE. ------ */',
            assets_tag: {
                'app.css':
                    '/* ----- APPLICATION CSS GOES HERE DURING COMPILATION. DO NOT REMOVE. ------ */',
                'blacklist.json':
                    '/* ----- BLACKLISTED GUILD IDS GOES HERE DURING COMPILATION. DO NOT REMOVE. ------ */',
                'settings.html':
                    '/* ----- SETTINGS GOES HERE DURING COMPILATION. DO NOT REMOVE. ------ */',
                'toolbar.html':
                    '/* ----- APPLICATION TOOLBAR GOES HERE DURING COMPILATION. DO NOT REMOVE. ------ */',
                'unlocker.html':
                    '/* ----- APPLICATION UNLOCKING GOES HERE DURING COMPILATION. DO NOT REMOVE. ------ */',
                'diceware.list':
                    '/* ------ DICEWARE PASSPHRASE WORD LIST GOES HERE DURING COMPILATION. DO NOT REMOVE ----- */'
            },
            assets_ignore_compression: [
                'diceware.list'
            ],
            library_info: {
                'sjcl.js': { requiresNode: true, requiresBrowser: false, minify: true },
                'scrypt.js': { requiresNode: true, requiresBrowser: false, minify: true },
                'sha3.js': { requiresNode: true, requiresBrowser: false, minify: true },
                'sidh.js': { requiresNode: true, requiresBrowser: false, minify: true },
                'smalltalk.js': { requiresNode: false, requiresBrowser: true, minify: true },
                'curve25519.js': { requiresNode: true, requiresBrowser: false, minify: true },
            },
            compression: false,
            plugin: './src/discordCrypt.plugin.js',
            assets: './src/assets',
            output: './build',
            lib: './lib',
        };

        let args = require( 'minimist' )( this.process.argv.slice( 2 ) );

        /* Display a help message. */
        if ( !args || args[ 'help' ] || args[ 'h' ] ) {
            console.info(
                "Usage:\n" +
                "   --plugin-path|-p         -  Path to the base plugin file to use.\n" +
                "   --tag-name|-t            -  The \"tag\" to use find and insert _libraries in the plugin file.\n" +
                "   --library-path|-l        -  The path to the library folder containing all needed files.\n" +
                "   --assets-directory|-a    -  The path to the assets folder containing add-in assets.\n" +
                "   --output-directory|-o    -  The output directory to store the compiled file in.\n" +
                "   --enable-compression|-c  -  If used, the plugin file will be compressed.\n" +
                "   --sign|-s                -  If specified, this is the key ID used to sign the built output.\n" +
                "\n" +
                "Example:\n" +
                `   ${this.process.argv[ 0 ]} ${this.process.argv[ 1 ]} ` +
                `-c -p "${defaults.plugin}" -l "${defaults.lib}" -o "${defaults.output}" -t "${defaults.library_tag}"` +
                `-a "${defaults.assets}"`
            );
            return;
        }

        console.info( `=============================================` );

        /* Compile with the arguments provided or defaults. */
        this.compilePlugin(
            args[ 'plugin-path' ] || args[ 'p' ] || defaults.plugin,
            args[ 'tag-name' ] || args[ 't' ] || defaults.library_tag,
            args[ 'library-path' ] || args[ 'l' ] || defaults.lib,
            defaults.library_info,
            args[ 'output-directory' ] || args[ 'o' ] || defaults.output,
            args[ 'assets-directory' ] || args[ 'a' ] || defaults.assets,
            args[ 'enable-compression' ] || args[ 'c' ] || defaults.compression,
            defaults.assets_tag,
            defaults.assets_ignore_compression,
            args[ 'sign' ] || args[ 's' ]
        );
    }
}

module.exports = { Compiler };

( new Compiler() ).run();
