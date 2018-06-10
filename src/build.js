/**
 * @public
 * @desc Compiles the plugin and adds all necessary libraries to it.
 */
class Compiler {

    /**
     * @public
     * @desc Resolves all necessary modules.
     */
    constructor() {
        /* Resolve general dependencies. */
        this.fs = require( 'fs' );
        this.path = require( 'path' );
        this.process = require( 'process' );
        this.uglifyjs = require( 'uglify-es' );

        this.defaultBuilderOptions = {
            parse: {
                bare_returns: true
            },
            mangle: true,
            sourceMap: { url: "inline" },
            compress: {
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
     * @private
     * @desc Reads all library files in the path specified and constructs an array string containing the data.
     * @param {string} library_path Relative path to look for all library files.
     * @returns {string} Returns a sanitized string containing the library name and the code.
     */
    readLibraries( library_path = './lib' ) {
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

            /* Read the file to a buffer. */
            let data = this.fs.readFileSync( this.path.join( library_path, file ) );

            /* Make sure something is returned. */
            if ( !data || !Buffer.isBuffer( data ) ) {
                console.error( `Failed to read library file: ${file} ...` );
                continue;
            }

            /* Try compressing the library. */
            try{
                let _data = this.uglifyjs.minify( data.toString(), this.defaultBuilderOptions );

                /* Skip on error. */
                if( _data.error !== undefined )
                    throw `${_data.error}`;
                else
                    data = _data.code;

                if( _data.warnings )
                    console.warn( _data.warnings );
            }
            catch(e){
                console.warn( `Warning: ${e.toString()} ...\nSkipping compression ...` );

                /* We still need to convert the Buffer() to a string. */
                data = data.toString();
            }

            /* Add it to the array. */
            libs[ file ] = data;
            count++;
        }

        console.info( `Read ${count} files from the library directory ...` );

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
     * @desc Compiles the plugin and adds all necessary libraries.
     * @param {string} plugin_path The path to the plugin file used as the base.
     * @param {string} tag_name The tag name to scan the [plugin] for to insert all libraries.
     * @param {string} library_path The path to the libraries used to add to the base file.
     * @param {string} output_dir The output directory to store the plugin.
     * @param {boolean} compress Whether to compress the plugin itself.
     * @return {boolean} Returns true on success and false on failure.
     */
    compilePlugin( plugin_path, tag_name, library_path, output_dir, compress ) {
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
        data = data.split( tag_name ).join( this.readLibraries( library_path ) );

        /* Construct the output path and name. */
        let output_path = this.path.join( output_dir, this.path.basename( plugin_path ) );

        /* Create the directory if it doesn't already exist. */
        try {
            this.fs.mkdirSync( output_dir );
        } catch ( e ) {
        }

        try {
            /* Only do this if we're compressing the plugin. */
            if( compress ){
                /* Compress the code. */
                data = this.uglifyjs.minify( data, this.defaultBuilderOptions );

                /* Check if an error occurred. */
                if( data.error !== undefined )
                    throw `${error}`;

                /* Update the variable. */
                data = header + data.code;
            }

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
            tag: '/* ----- LIBRARY DEFINITIONS GO HERE DURING COMPILATION. DO NOT REMOVE. ------ */',
            plugin: './src/discordCrypt.plugin.js',
            compression: false,
            output: './build',
            lib: './lib',
        };

        let args = require( 'minimist' )( this.process.argv.slice( 2 ) );

        /* Display a help message.*/
        if( !args || args[ 'help' ] || args[ 'h' ] ){
            console.info(
                "Usage:\n" +
                "   --plugin-path|-p         -  Path to the base plugin file to use.\n" +
                "   --tag-name|-t            -  The \"tag\" to use find and insert libraries in the plugin file.\n" +
                "   --library-path|-l        -  The path to the library folder containing all needed files.\n" +
                "   --output-directory|-o    -  The output directory to store the compiled file in.\n" +
                "   --enable-compression|-c  -  If used, the plugin file will be compressed.\n" +
                "\n" +
                "Example:\n" +
                `   ${this.process.argv[0]} ${this.process.argv[1]} ` +
                    `-c -p "${defaults.plugin}" -l "${defaults.lib}" -o "${defaults.output}" -t "${defaults.tag}"`

            );
            return;
        }

        /* Compile with the arguments provided or defaults. */
        this.compilePlugin(
            args['plugin-path'] || args[ 'p' ] || defaults.plugin,
            args['tag-name'] || args[ 't' ] || defaults.tag,
            args['library-path'] || args[ 'l' ] || defaults.lib,
            args['output-directory'] || args[ 'o' ] || defaults.output,
            args['enable-compression'] || args[ 'c' ] || defaults.compression
        );
    }
}

(new Compiler()).run();
