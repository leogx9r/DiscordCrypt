/**
 * @public
 * @desc Compiles the plugin and adds all necessary libraries to it.
 */
class Compiler {

    /**
     * @typedef {Object} LibraryInfo
     * @desc Contains the library and necessary information.
     * @property {boolean} requiresElectron Whether this library relies on Electron's internal support.
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
     * @public
     * @desc Resolves all necessary modules.
     */
    constructor() {
        /**
         * @desc Cache the FS module for file operations.
         * @type {module:fs}
         */
        this.fs = require( 'fs' );

        /**
         * @desc Cache the PATH module for constructing relative and absolute paths.
         * @type {module:path}
         */
        this.path = require( 'path' );

        /**
         * @desc Cache the PROCESS module for argument retrieval.
         * @type {NodeJS.Process}
         */
        this.process = require( 'process' );

        /**
         * @desc Cache the Uglify-JS ( ES ) Module for compressing sources.
         */
        this.uglifyjs = require( 'uglify-es' );

        /**
         * @desc Defines the default options applied to libraries and optionally the main module if enabled.
         * @type {Object}
         */
        this.defaultBuilderOptions = {
            parse: {
                bare_returns: true
            },
            mangle: true,
            sourceMap: { url: "inline" },
            compress: {
                ecma: 6,
                toplevel: true,
                dead_code: true,
                unsafe_Function: true,
                unsafe_methods: true,
                unused: false
            },
            output: {
                ascii_only: true,
                beautify: false,
            },
            warnings: true,
        };
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
     * @private
     * @desc Reads all library files in the path specified and constructs an array string containing the data.
     * @param {string} library_path Relative path to look for all library files.
     * @param {LibraryDefinition} library_info A list of the info requires to add to a library.
     * @returns {string} Returns a sanitized string containing the library name and the code.
     */
    readLibraries( library_path = './lib', library_info = {} ) {
        let libs = {}, count = 0;
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
            if( !library_info.hasOwnProperty( base ) ) {
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

            /* Try compressing the library. */
            data = this.tryMinify( data );

            /* Update the code in the library info. */
            library_info[ base ][ 'code' ] = data;

            /* Add it to the array. */
            libs[ file ] = library_info[ base ];
            count++;

            /* Quick log. */
            console.info( `Added library: [ ${base} ] ...` );
        }

        console.info( `Added ${count} files from the library directory ...` );

        /* Construct a sanitized array string. */
        for ( let id in libs )
            str += `            '${id}': ${JSON.stringify( libs[ id ] )},\n`;

        /* Remove the last comma added by the above loop. */
        str = str.slice( 0, str.length - 1 - 1 );

        /* Return the full string. */
        return str;
    }

    /**
     * @private
     * @desc Reads all asset files in the path specified and replaces them in the base file.
     * @param {string} asset_path The path to the assets directory.
     * @param {string} original_data The original base file data.
     * @param {Object} constants Object containing the tags for each file to replace.
     */
    compileAssets( asset_path = './assets', original_data, constants ) {
        /* Read all files in the specified directory. */
        let files = this.fs.readdirSync( asset_path );

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

            data = data.split( "\r" ).join( "" ).split( "\n" ).join( '' ).split( '    ' ).join( ' ' );

            /* Replace the data. */
            original_data = original_data.split( constants[ file_name ] ).join( data );

            /* Quick log. */
            console.info( `Added asset: [ ${this.path.basename( file )} ] ...` );
        }

        return original_data;
    }


    /**
     * @private
     * @desc Compiles the plugin and adds all necessary libraries.
     * @param {string} plugin_path The path to the plugin file used as the base.
     * @param {string} tag_name The tag name to scan the [plugin] for to insert all libraries.
     * @param {string} library_path The path to the libraries used to add to the base file.
     * @param {LibraryDefinition} library_info Required library info.
     * @param {string} output_dir The output directory to store the plugin.
     * @param {string} assets_path The path to the assets directory.
     * @param {boolean} compress Whether to compress the plugin itself.
     * @param {Object} assets_data The asset tags for each file within the assets directory.
     * @return {boolean} Returns true on success and false on failure.
     */
    compilePlugin( plugin_path, tag_name, library_path, library_info, output_dir, assets_path, compress, assets_data ) {
        const header =
            `//META{"name":"discordCrypt"}*//

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
 ******************************************************************************/\n\n`;

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
        /* Compile all libraries and replace the tag with them. */
        data = data.split( tag_name ).join( this.readLibraries( library_path, library_info ) );

        /* Construct the output path and name. */
        let output_path = this.path.join( output_dir, this.path.basename( plugin_path ) );

        /* Create the directory if it doesn't already exist. */
        try {
            this.fs.mkdirSync( output_dir );
        } catch ( e ) {
            console.info( 'Directory already exists. Skipping creation ...' );
        }

        /* Add all assets. */
        data = this.compileAssets( assets_path, data, assets_data );

        /* Only do this if we're compressing the plugin. */
        if ( compress )
            data = header + this.tryMinify( data, true );

        try {
            /* Write the file to the output. */
            this.fs.writeFileSync( output_path, data );
        }
        catch ( e ) {
            console.error( `Error building plugin:\n    ${e.toString()}` );
            return false;
        }

        /* Signal to the user. */
        console.info( `Built plugin file!\nDestination: ${output_path}` );

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
                'settings.html':
                    '/* ----- SETTINGS GOES HERE DURING COMPILATION. DO NOT REMOVE. ------ */',
                'toolbar.html':
                    '/* ----- APPLICATION TOOLBAR GOES HERE DURING COMPILATION. DO NOT REMOVE. ------ */',
                'unlocker.html':
                    '/* ----- APPLICATION UNLOCKING GOES HERE DURING COMPILATION. DO NOT REMOVE. ------ */',
            },
            library_info: {
                'sjcl.js': { requiresElectron: true, requiresBrowser: false },
                'smalltalk.js': { requiresElectron: false, requiresBrowser: true },
                'currify.js': { requiresElectron: false, requiresBrowser: true },
                'curve25519.js': { requiresElectron: true, requiresBrowser: false },
            },
            compression: false,
            plugin: './src/discordCrypt.plugin.js',
            assets: './src/assets',
            output: './build',
            lib: './lib',
        };

        let args = require( 'minimist' )( this.process.argv.slice( 2 ) );

        /* Display a help message.*/
        if ( !args || args[ 'help' ] || args[ 'h' ] ) {
            console.info(
                "Usage:\n" +
                "   --plugin-path|-p         -  Path to the base plugin file to use.\n" +
                "   --tag-name|-t            -  The \"tag\" to use find and insert libraries in the plugin file.\n" +
                "   --library-path|-l        -  The path to the library folder containing all needed files.\n" +
                "   --assets-directory|-a    -  The path to the assets folder containing add-in assets.\n" +
                "   --output-directory|-o    -  The output directory to store the compiled file in.\n" +
                "   --enable-compression|-c  -  If used, the plugin file will be compressed.\n" +
                "\n" +
                "Example:\n" +
                `   ${this.process.argv[ 0 ]} ${this.process.argv[ 1 ]} ` +
                `-c -p "${defaults.plugin}" -l "${defaults.lib}" -o "${defaults.output}" -t "${defaults.library_tag}"` +
                `-a "${defaults.assets}"`
            );
            return;
        }

        /* Compile with the arguments provided or defaults. */
        this.compilePlugin(
            args[ 'plugin-path' ] || args[ 'p' ] || defaults.plugin,
            args[ 'tag-name' ] || args[ 't' ] || defaults.library_tag,
            args[ 'library-path' ] || args[ 'l' ] || defaults.lib,
            defaults.library_info,
            args[ 'output-directory' ] || args[ 'o' ] || defaults.output,
            args[ 'assets-directory' ] || args[ 'a' ] || defaults.assets,
            args[ 'enable-compression' ] || args[ 'c' ] || defaults.compression,
            defaults.assets_tag
        );
    }
}

module.exports = { Compiler };

(new Compiler()).run();
