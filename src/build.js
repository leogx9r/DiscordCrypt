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
                console.log( `Skipping non-javascript file in "${library_path}" - ${file} ...` );
                continue;
            }

            /* Read the file to a buffer. */
            let data = this.fs.readFileSync( this.path.join( library_path, file ) );

            /* Make sure something is returned. */
            if ( !data || !Buffer.isBuffer( data ) ) {
                console.log( `Failed to read library file: ${file} ...` );
                continue;
            }

            /* Add it to the array. */
            libs[ file ] = data.toString();
            count++;
        }

        console.log( `Read ${count} files from the library directory ...` );

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
     * @return {boolean} Returns true on success and false on failure.
     */
    compilePlugin( plugin_path, tag_name, library_path, output_dir ) {
        /* Read the plugin file. */
        let data = this.fs.readFileSync( plugin_path );

        /* Make sure something was read. */
        if ( !data || !Buffer.isBuffer( data ) ) {
            console.log( `Failed to read library file: ${file} ...` );
            return false;
        }

        /* Convert the read data to a string. */
        data = data.toString();

        /* Make sure the tag is present in the file. */
        if ( data.lastIndexOf( tag_name ) === -1 ) {
            console.log( `Failed to locate the tag in the plugin file ...` );
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

        /* Write the file to the output. */
        try {
            this.fs.writeFileSync( output_path, data );
        }
        catch ( e ) {
            console.log( `Error building plugin:\n    ${e.toString()}` );
            return false;
        }

        /* Signal to the user. */
        console.log( `Built plugin file!\nDestination: ${output_path}` );

        return true;
    }

    /**
     * @public
     * @desc Parses the command line arguments are runs the compiler.
     */
    run() {
        /* Construct the default arguments. */
        const defaults = {
            plugin: './src/discordCrypt.plugin.js',
            tag: '/* ----- LIBRARY DEFINITIONS GO HERE DURING COMPILATION. DO NOT REMOVE. ------ */',
            lib: './lib',
            output: './build'
        };

        let args = require( 'minimist' )( this.process.argv.slice( 2 ) );

        /* Display a help message.*/
        if( !args || args[ 'help' ] || args[ 'h' ] ){
            console.log(
                "Usage:\n" +
                "   --plugin-path|-p       -  Path to the base plugin file to use.\n" +
                "   --tag-name|-t          -  The \"tag\" to use find and insert libraries in the plugin file.\n" +
                "   --library-path|-l      -  The path to the library folder containing all needed files.\n" +
                "   --output-directory|-o  -  The output directory to store the compiled file in.\n" +
                "\n" +
                "Example:\n" +
                `   ${this.process.argv[0]} ${this.process.argv[1]} ` +
                `-p "${defaults.plugin}" -l "${defaults.lib}" -o "${defaults.output}" -t "${defaults.tag}"`

            );
            return;
        }

        /* Compile with the arguments provided or defaults. */
        this.compilePlugin(
            args['plugin-path'] || args[ 'p' ] || defaults.plugin,
            args['tag-name'] || args[ 't' ] || defaults.tag,
            args['library-path'] || args[ 'l' ] || defaults.lib,
            args['output-directory'] || args[ 'o' ] || defaults.output
        );
    }
}

(new Compiler()).run();
