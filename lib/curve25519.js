/**
 The MIT License (MIT)

 Copyright (c) 2016

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

// Taken from https://github.com/wavesplatform/curve25519-js

'use strict';

// Curve25519 signatures (and also key agreement)
// like in the early Axolotl.
//
// Written by Dmitry Chestnykh.
// You can use it under MIT or CC0 license.

// Curve25519 signatures idea and math by Trevor Perrin
// https://moderncrypto.org/mail-archive/curves/2014/000205.html

// Derived from TweetNaCl.js (https://tweetnacl.js.org/)
// Ported in 2014 by Dmitry Chestnykh and Devi Mandiri.
// Public domain.
//
// Implementation derived from TweetNaCl version 20140427.
// See for details: http://tweetnacl.cr.yp.to/

class curve25519 {

    static init_25519_constants( init ) {
        const r = new Float64Array( 16 );

        if ( init )
            for ( let i = 0; i < init.length; i++ )
                r[ i ] = init[ i ];

        return r;
    }

    static gf0() {
        return curve25519.init_25519_constants()
    };

    static gf1() {
        return curve25519.init_25519_constants( [ 1 ] )
    };

    static _121665() {
        return curve25519.init_25519_constants( [ 0xdb41, 1 ] )
    };

    static D() {
        return curve25519.init_25519_constants( [
            0x78a3, 0x1359, 0x4dca, 0x75eb,
            0xd8ab, 0x4141, 0x0a4d, 0x0070,
            0xe898, 0x7779, 0x4079, 0x8cc7,
            0xfe73, 0x2b6f, 0x6cee, 0x5203
        ] )
    };

    static D2() {
        return curve25519.init_25519_constants( [
            0xf159, 0x26b2, 0x9b94, 0xebd6,
            0xb156, 0x8283, 0x149a, 0x00e0,
            0xd130, 0xeef3, 0x80f2, 0x198e,
            0xfce7, 0x56df, 0xd9dc, 0x2406
        ] );
    }

    static X() {
        return curve25519.init_25519_constants( [
            0xd51a, 0x8f25, 0x2d60, 0xc956,
            0xa7b2, 0x9525, 0xc760, 0x692c,
            0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
            0x53fe, 0xcd6e, 0x36d3, 0x2169
        ] );
    }

    static Y() {
        return curve25519.init_25519_constants( [
            0x6658, 0x6666, 0x6666, 0x6666,
            0x6666, 0x6666, 0x6666, 0x6666,
            0x6666, 0x6666, 0x6666, 0x6666,
            0x6666, 0x6666, 0x6666, 0x6666
        ] );
    }

    static I() {
        return curve25519.init_25519_constants( [
            0xa0b0, 0x4a0e, 0x1b27, 0xc4ee,
            0xe478, 0xad2f, 0x1806, 0x2f43,
            0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
            0xdf0b, 0x4fc1, 0x2480, 0x2b83
        ] );
    }

    static checkArrayTypes() {
        let t;

        for ( let i = 0; i < arguments.length; i++ ) {
            if ( ( t = Object.prototype.toString.call( arguments[ i ] ) ) !== '[object Uint8Array]' )
                throw new TypeError( `unexpected type ${t}, use Uint8Array` );
        }
    }

    static crypto_verify_32( x, xi, y, yi ) {
        function vn( x, xi, y, yi, n ) {
            let i, d = 0;
            for ( i = 0; i < n; i++ ) d |= x[ xi + i ] ^ y[ yi + i ];
            return ( 1 & d - 1 >>> 8 ) - 1;
        }

        return vn( x, xi, y, yi, 32 );
    }

    static set25519( r, a ) {
        let i;
        for ( i = 0; i < 16; i++ ) r[ i ] = a[ i ] | 0;
    }

    static sel25519( p, q, b ) {
        let t;
        const c = ~( b - 1 );
        for ( let i = 0; i < 16; i++ ) {
            t = c & ( p[ i ] ^ q[ i ] );
            p[ i ] ^= t;
            q[ i ] ^= t;
        }
    }

    static pack25519( o, n ) {
        function car25519( o ) {
            let i, v, c = 1;
            for ( i = 0; i < 16; i++ ) {
                v = o[ i ] + c + 65535;
                c = Math.floor( v / 65536 );
                o[ i ] = v - c * 65536;
            }
            o[ 0 ] += c - 1 + 37 * ( c - 1 );
        }

        let i, j, b;
        const m = curve25519.init_25519_constants(), t = curve25519.init_25519_constants();
        for ( i = 0; i < 16; i++ ) t[ i ] = n[ i ];
        car25519( t );
        car25519( t );
        car25519( t );
        for ( j = 0; j < 2; j++ ) {
            m[ 0 ] = t[ 0 ] - 0xffed;
            for ( i = 1; i < 15; i++ ) {
                m[ i ] = t[ i ] - 0xffff - ( m[ i - 1 ] >> 16 & 1 );
                m[ i - 1 ] &= 0xffff;
            }
            m[ 15 ] = t[ 15 ] - 0x7fff - ( m[ 14 ] >> 16 & 1 );
            b = m[ 15 ] >> 16 & 1;
            m[ 14 ] &= 0xffff;
            curve25519.sel25519( t, m, 1 - b );
        }
        for ( i = 0; i < 16; i++ ) {
            o[ 2 * i ] = t[ i ] & 0xff;
            o[ 2 * i + 1 ] = t[ i ] >> 8;
        }
    }

    static par25519( a ) {
        const d = new Uint8Array( 32 );
        curve25519.pack25519( d, a );
        return d[ 0 ] & 1;
    }

    static unpack25519( o, n ) {
        let i;
        for ( i = 0; i < 16; i++ ) o[ i ] = n[ 2 * i ] + ( n[ 2 * i + 1 ] << 8 );
        o[ 15 ] &= 0x7fff;
    }

    static blockadd( o, a, b ) {
        for ( let i = 0; i < 16; i++ ) o[ i ] = a[ i ] + b[ i ];
    }

    static blocksub( o, a, b ) {
        for ( let i = 0; i < 16; i++ ) o[ i ] = a[ i ] - b[ i ];
    }

    static blockround( o, a, b ) {
        let v, c,
            t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0,
            t8 = 0, t9 = 0, t10 = 0, t11 = 0, t12 = 0, t13 = 0, t14 = 0, t15 = 0,
            t16 = 0, t17 = 0, t18 = 0, t19 = 0, t20 = 0, t21 = 0, t22 = 0, t23 = 0,
            t24 = 0, t25 = 0, t26 = 0, t27 = 0, t28 = 0, t29 = 0, t30 = 0;
        const b0 = b[ 0 ],
            b1 = b[ 1 ],
            b2 = b[ 2 ],
            b3 = b[ 3 ],
            b4 = b[ 4 ],
            b5 = b[ 5 ],
            b6 = b[ 6 ],
            b7 = b[ 7 ],
            b8 = b[ 8 ],
            b9 = b[ 9 ],
            b10 = b[ 10 ],
            b11 = b[ 11 ],
            b12 = b[ 12 ],
            b13 = b[ 13 ],
            b14 = b[ 14 ],
            b15 = b[ 15 ];

        v = a[ 0 ];
        t0 += v * b0;
        t1 += v * b1;
        t2 += v * b2;
        t3 += v * b3;
        t4 += v * b4;
        t5 += v * b5;
        t6 += v * b6;
        t7 += v * b7;
        t8 += v * b8;
        t9 += v * b9;
        t10 += v * b10;
        t11 += v * b11;
        t12 += v * b12;
        t13 += v * b13;
        t14 += v * b14;
        t15 += v * b15;
        v = a[ 1 ];
        t1 += v * b0;
        t2 += v * b1;
        t3 += v * b2;
        t4 += v * b3;
        t5 += v * b4;
        t6 += v * b5;
        t7 += v * b6;
        t8 += v * b7;
        t9 += v * b8;
        t10 += v * b9;
        t11 += v * b10;
        t12 += v * b11;
        t13 += v * b12;
        t14 += v * b13;
        t15 += v * b14;
        t16 += v * b15;
        v = a[ 2 ];
        t2 += v * b0;
        t3 += v * b1;
        t4 += v * b2;
        t5 += v * b3;
        t6 += v * b4;
        t7 += v * b5;
        t8 += v * b6;
        t9 += v * b7;
        t10 += v * b8;
        t11 += v * b9;
        t12 += v * b10;
        t13 += v * b11;
        t14 += v * b12;
        t15 += v * b13;
        t16 += v * b14;
        t17 += v * b15;
        v = a[ 3 ];
        t3 += v * b0;
        t4 += v * b1;
        t5 += v * b2;
        t6 += v * b3;
        t7 += v * b4;
        t8 += v * b5;
        t9 += v * b6;
        t10 += v * b7;
        t11 += v * b8;
        t12 += v * b9;
        t13 += v * b10;
        t14 += v * b11;
        t15 += v * b12;
        t16 += v * b13;
        t17 += v * b14;
        t18 += v * b15;
        v = a[ 4 ];
        t4 += v * b0;
        t5 += v * b1;
        t6 += v * b2;
        t7 += v * b3;
        t8 += v * b4;
        t9 += v * b5;
        t10 += v * b6;
        t11 += v * b7;
        t12 += v * b8;
        t13 += v * b9;
        t14 += v * b10;
        t15 += v * b11;
        t16 += v * b12;
        t17 += v * b13;
        t18 += v * b14;
        t19 += v * b15;
        v = a[ 5 ];
        t5 += v * b0;
        t6 += v * b1;
        t7 += v * b2;
        t8 += v * b3;
        t9 += v * b4;
        t10 += v * b5;
        t11 += v * b6;
        t12 += v * b7;
        t13 += v * b8;
        t14 += v * b9;
        t15 += v * b10;
        t16 += v * b11;
        t17 += v * b12;
        t18 += v * b13;
        t19 += v * b14;
        t20 += v * b15;
        v = a[ 6 ];
        t6 += v * b0;
        t7 += v * b1;
        t8 += v * b2;
        t9 += v * b3;
        t10 += v * b4;
        t11 += v * b5;
        t12 += v * b6;
        t13 += v * b7;
        t14 += v * b8;
        t15 += v * b9;
        t16 += v * b10;
        t17 += v * b11;
        t18 += v * b12;
        t19 += v * b13;
        t20 += v * b14;
        t21 += v * b15;
        v = a[ 7 ];
        t7 += v * b0;
        t8 += v * b1;
        t9 += v * b2;
        t10 += v * b3;
        t11 += v * b4;
        t12 += v * b5;
        t13 += v * b6;
        t14 += v * b7;
        t15 += v * b8;
        t16 += v * b9;
        t17 += v * b10;
        t18 += v * b11;
        t19 += v * b12;
        t20 += v * b13;
        t21 += v * b14;
        t22 += v * b15;
        v = a[ 8 ];
        t8 += v * b0;
        t9 += v * b1;
        t10 += v * b2;
        t11 += v * b3;
        t12 += v * b4;
        t13 += v * b5;
        t14 += v * b6;
        t15 += v * b7;
        t16 += v * b8;
        t17 += v * b9;
        t18 += v * b10;
        t19 += v * b11;
        t20 += v * b12;
        t21 += v * b13;
        t22 += v * b14;
        t23 += v * b15;
        v = a[ 9 ];
        t9 += v * b0;
        t10 += v * b1;
        t11 += v * b2;
        t12 += v * b3;
        t13 += v * b4;
        t14 += v * b5;
        t15 += v * b6;
        t16 += v * b7;
        t17 += v * b8;
        t18 += v * b9;
        t19 += v * b10;
        t20 += v * b11;
        t21 += v * b12;
        t22 += v * b13;
        t23 += v * b14;
        t24 += v * b15;
        v = a[ 10 ];
        t10 += v * b0;
        t11 += v * b1;
        t12 += v * b2;
        t13 += v * b3;
        t14 += v * b4;
        t15 += v * b5;
        t16 += v * b6;
        t17 += v * b7;
        t18 += v * b8;
        t19 += v * b9;
        t20 += v * b10;
        t21 += v * b11;
        t22 += v * b12;
        t23 += v * b13;
        t24 += v * b14;
        t25 += v * b15;
        v = a[ 11 ];
        t11 += v * b0;
        t12 += v * b1;
        t13 += v * b2;
        t14 += v * b3;
        t15 += v * b4;
        t16 += v * b5;
        t17 += v * b6;
        t18 += v * b7;
        t19 += v * b8;
        t20 += v * b9;
        t21 += v * b10;
        t22 += v * b11;
        t23 += v * b12;
        t24 += v * b13;
        t25 += v * b14;
        t26 += v * b15;
        v = a[ 12 ];
        t12 += v * b0;
        t13 += v * b1;
        t14 += v * b2;
        t15 += v * b3;
        t16 += v * b4;
        t17 += v * b5;
        t18 += v * b6;
        t19 += v * b7;
        t20 += v * b8;
        t21 += v * b9;
        t22 += v * b10;
        t23 += v * b11;
        t24 += v * b12;
        t25 += v * b13;
        t26 += v * b14;
        t27 += v * b15;
        v = a[ 13 ];
        t13 += v * b0;
        t14 += v * b1;
        t15 += v * b2;
        t16 += v * b3;
        t17 += v * b4;
        t18 += v * b5;
        t19 += v * b6;
        t20 += v * b7;
        t21 += v * b8;
        t22 += v * b9;
        t23 += v * b10;
        t24 += v * b11;
        t25 += v * b12;
        t26 += v * b13;
        t27 += v * b14;
        t28 += v * b15;
        v = a[ 14 ];
        t14 += v * b0;
        t15 += v * b1;
        t16 += v * b2;
        t17 += v * b3;
        t18 += v * b4;
        t19 += v * b5;
        t20 += v * b6;
        t21 += v * b7;
        t22 += v * b8;
        t23 += v * b9;
        t24 += v * b10;
        t25 += v * b11;
        t26 += v * b12;
        t27 += v * b13;
        t28 += v * b14;
        t29 += v * b15;
        v = a[ 15 ];
        t15 += v * b0;
        t16 += v * b1;
        t17 += v * b2;
        t18 += v * b3;
        t19 += v * b4;
        t20 += v * b5;
        t21 += v * b6;
        t22 += v * b7;
        t23 += v * b8;
        t24 += v * b9;
        t25 += v * b10;
        t26 += v * b11;
        t27 += v * b12;
        t28 += v * b13;
        t29 += v * b14;
        t30 += v * b15;

        t0 += 38 * t16;
        t1 += 38 * t17;
        t2 += 38 * t18;
        t3 += 38 * t19;
        t4 += 38 * t20;
        t5 += 38 * t21;
        t6 += 38 * t22;
        t7 += 38 * t23;
        t8 += 38 * t24;
        t9 += 38 * t25;
        t10 += 38 * t26;
        t11 += 38 * t27;
        t12 += 38 * t28;
        t13 += 38 * t29;
        t14 += 38 * t30;
        // t15 left as is

        // first car
        c = 1;
        v = t0 + c + 65535;
        c = Math.floor( v / 65536 );
        t0 = v - c * 65536;
        v = t1 + c + 65535;
        c = Math.floor( v / 65536 );
        t1 = v - c * 65536;
        v = t2 + c + 65535;
        c = Math.floor( v / 65536 );
        t2 = v - c * 65536;
        v = t3 + c + 65535;
        c = Math.floor( v / 65536 );
        t3 = v - c * 65536;
        v = t4 + c + 65535;
        c = Math.floor( v / 65536 );
        t4 = v - c * 65536;
        v = t5 + c + 65535;
        c = Math.floor( v / 65536 );
        t5 = v - c * 65536;
        v = t6 + c + 65535;
        c = Math.floor( v / 65536 );
        t6 = v - c * 65536;
        v = t7 + c + 65535;
        c = Math.floor( v / 65536 );
        t7 = v - c * 65536;
        v = t8 + c + 65535;
        c = Math.floor( v / 65536 );
        t8 = v - c * 65536;
        v = t9 + c + 65535;
        c = Math.floor( v / 65536 );
        t9 = v - c * 65536;
        v = t10 + c + 65535;
        c = Math.floor( v / 65536 );
        t10 = v - c * 65536;
        v = t11 + c + 65535;
        c = Math.floor( v / 65536 );
        t11 = v - c * 65536;
        v = t12 + c + 65535;
        c = Math.floor( v / 65536 );
        t12 = v - c * 65536;
        v = t13 + c + 65535;
        c = Math.floor( v / 65536 );
        t13 = v - c * 65536;
        v = t14 + c + 65535;
        c = Math.floor( v / 65536 );
        t14 = v - c * 65536;
        v = t15 + c + 65535;
        c = Math.floor( v / 65536 );
        t15 = v - c * 65536;
        t0 += c - 1 + 37 * ( c - 1 );

        // second car
        c = 1;
        v = t0 + c + 65535;
        c = Math.floor( v / 65536 );
        t0 = v - c * 65536;
        v = t1 + c + 65535;
        c = Math.floor( v / 65536 );
        t1 = v - c * 65536;
        v = t2 + c + 65535;
        c = Math.floor( v / 65536 );
        t2 = v - c * 65536;
        v = t3 + c + 65535;
        c = Math.floor( v / 65536 );
        t3 = v - c * 65536;
        v = t4 + c + 65535;
        c = Math.floor( v / 65536 );
        t4 = v - c * 65536;
        v = t5 + c + 65535;
        c = Math.floor( v / 65536 );
        t5 = v - c * 65536;
        v = t6 + c + 65535;
        c = Math.floor( v / 65536 );
        t6 = v - c * 65536;
        v = t7 + c + 65535;
        c = Math.floor( v / 65536 );
        t7 = v - c * 65536;
        v = t8 + c + 65535;
        c = Math.floor( v / 65536 );
        t8 = v - c * 65536;
        v = t9 + c + 65535;
        c = Math.floor( v / 65536 );
        t9 = v - c * 65536;
        v = t10 + c + 65535;
        c = Math.floor( v / 65536 );
        t10 = v - c * 65536;
        v = t11 + c + 65535;
        c = Math.floor( v / 65536 );
        t11 = v - c * 65536;
        v = t12 + c + 65535;
        c = Math.floor( v / 65536 );
        t12 = v - c * 65536;
        v = t13 + c + 65535;
        c = Math.floor( v / 65536 );
        t13 = v - c * 65536;
        v = t14 + c + 65535;
        c = Math.floor( v / 65536 );
        t14 = v - c * 65536;
        v = t15 + c + 65535;
        c = Math.floor( v / 65536 );
        t15 = v - c * 65536;
        t0 += c - 1 + 37 * ( c - 1 );

        o[ 0 ] = t0;
        o[ 1 ] = t1;
        o[ 2 ] = t2;
        o[ 3 ] = t3;
        o[ 4 ] = t4;
        o[ 5 ] = t5;
        o[ 6 ] = t6;
        o[ 7 ] = t7;
        o[ 8 ] = t8;
        o[ 9 ] = t9;
        o[ 10 ] = t10;
        o[ 11 ] = t11;
        o[ 12 ] = t12;
        o[ 13 ] = t13;
        o[ 14 ] = t14;
        o[ 15 ] = t15;
    }

    static blockround_dest( o, a ) {
        curve25519.blockround( o, a, a );
    }

    static inv25519( o, i ) {
        const c = curve25519.init_25519_constants();
        let a;
        for ( a = 0; a < 16; a++ ) c[ a ] = i[ a ];
        for ( a = 253; a >= 0; a-- ) {
            curve25519.blockround_dest( c, c );
            if ( a !== 2 && a !== 4 ) curve25519.blockround( c, c, i );
        }
        for ( a = 0; a < 16; a++ ) o[ a ] = c[ a ];
    }

    static crypto_scalarmult( q, n, p ) {
        const z = new Uint8Array( 32 );
        const x = new Float64Array( 80 );
        let r, i;
        const a = curve25519.init_25519_constants(), b = curve25519.init_25519_constants(),
            c = curve25519.init_25519_constants(), d = curve25519.init_25519_constants(),
            e = curve25519.init_25519_constants(), f = curve25519.init_25519_constants();
        for ( i = 0; i < 31; i++ ) z[ i ] = n[ i ];
        z[ 31 ] = n[ 31 ] & 127 | 64;
        z[ 0 ] &= 248;
        curve25519.unpack25519( x, p );
        for ( i = 0; i < 16; i++ ) {
            b[ i ] = x[ i ];
            d[ i ] = a[ i ] = c[ i ] = 0;
        }
        a[ 0 ] = d[ 0 ] = 1;
        for ( i = 254; i >= 0; --i ) {
            r = z[ i >>> 3 ] >>> ( i & 7 ) & 1;
            curve25519.sel25519( a, b, r );
            curve25519.sel25519( c, d, r );
            curve25519.blockadd( e, a, c );
            curve25519.blocksub( a, a, c );
            curve25519.blockadd( c, b, d );
            curve25519.blocksub( b, b, d );
            curve25519.blockround_dest( d, e );
            curve25519.blockround_dest( f, a );
            curve25519.blockround( a, c, a );
            curve25519.blockround( c, b, e );
            curve25519.blockadd( e, a, c );
            curve25519.blocksub( a, a, c );
            curve25519.blockround_dest( b, a );
            curve25519.blocksub( c, d, f );
            curve25519.blockround( a, c, curve25519._121665() );
            curve25519.blockadd( a, a, d );
            curve25519.blockround( c, c, a );
            curve25519.blockround( a, d, f );
            curve25519.blockround( d, b, x );
            curve25519.blockround_dest( b, e );
            curve25519.sel25519( a, b, r );
            curve25519.sel25519( c, d, r );
        }
        for ( i = 0; i < 16; i++ ) {
            x[ i + 16 ] = a[ i ];
            x[ i + 32 ] = c[ i ];
            x[ i + 48 ] = b[ i ];
            x[ i + 64 ] = d[ i ];
        }
        const x32 = x.subarray( 32 );
        const x16 = x.subarray( 16 );
        curve25519.inv25519( x32, x32 );
        curve25519.blockround( x16, x16, x32 );
        curve25519.pack25519( q, x16 );
        return 0;
    }

    static crypto_hash( out, m, n ) {
        function ts64( x, i, h, l ) {
            x[ i ] = h >> 24 & 0xff;
            x[ i + 1 ] = h >> 16 & 0xff;
            x[ i + 2 ] = h >> 8 & 0xff;
            x[ i + 3 ] = h & 0xff;
            x[ i + 4 ] = l >> 24 & 0xff;
            x[ i + 5 ] = l >> 16 & 0xff;
            x[ i + 6 ] = l >> 8 & 0xff;
            x[ i + 7 ] = l & 0xff;
        }

        function crypto_hashblocks_hl( hh, hl, m, n ) {
            const K = [
                0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd,
                0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
                0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
                0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
                0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe,
                0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
                0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1,
                0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
                0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
                0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
                0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483,
                0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
                0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210,
                0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
                0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
                0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
                0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926,
                0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
                0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8,
                0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
                0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
                0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
                0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910,
                0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
                0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53,
                0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
                0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
                0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
                0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60,
                0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
                0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9,
                0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
                0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
                0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
                0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6,
                0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
                0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493,
                0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
                0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
                0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
            ];

            const wh = new Int32Array( 16 ), wl = new Int32Array( 16 );
            let bh0, bh1, bh2, bh3, bh4, bh5, bh6, bh7,
                bl0, bl1, bl2, bl3, bl4, bl5, bl6, bl7,
                th, tl, i, j, h, l, a, b, c, d;

            let ah0 = hh[ 0 ],
                ah1 = hh[ 1 ],
                ah2 = hh[ 2 ],
                ah3 = hh[ 3 ],
                ah4 = hh[ 4 ],
                ah5 = hh[ 5 ],
                ah6 = hh[ 6 ],
                ah7 = hh[ 7 ],

                al0 = hl[ 0 ],
                al1 = hl[ 1 ],
                al2 = hl[ 2 ],
                al3 = hl[ 3 ],
                al4 = hl[ 4 ],
                al5 = hl[ 5 ],
                al6 = hl[ 6 ],
                al7 = hl[ 7 ];

            let pos = 0;
            while ( n >= 128 ) {
                for ( i = 0; i < 16; i++ ) {
                    j = 8 * i + pos;
                    wh[ i ] = m[ j + 0 ] << 24 | m[ j + 1 ] << 16 | m[ j + 2 ] << 8 | m[ j + 3 ];
                    wl[ i ] = m[ j + 4 ] << 24 | m[ j + 5 ] << 16 | m[ j + 6 ] << 8 | m[ j + 7 ];
                }
                for ( i = 0; i < 80; i++ ) {
                    bh0 = ah0;
                    bh1 = ah1;
                    bh2 = ah2;
                    bh3 = ah3;
                    bh4 = ah4;
                    bh5 = ah5;
                    bh6 = ah6;
                    bh7 = ah7;

                    bl0 = al0;
                    bl1 = al1;
                    bl2 = al2;
                    bl3 = al3;
                    bl4 = al4;
                    bl5 = al5;
                    bl6 = al6;
                    bl7 = al7;

                    // add
                    h = ah7;
                    l = al7;

                    a = l & 0xffff;
                    b = l >>> 16;
                    c = h & 0xffff;
                    d = h >>> 16;

                    // Sigma1
                    h = ( ah4 >>> 14 | al4 << 32 - 14 ) ^ ( ah4 >>> 18 | al4 << 32 - 18 ) ^
                        ( al4 >>> 41 - 32 | ah4 << 23 );
                    l = ( al4 >>> 14 | ah4 << 32 - 14 ) ^ ( al4 >>> 18 | ah4 << 32 - 18 ) ^
                        ( ah4 >>> 41 - 32 | al4 << 23 );

                    a += l & 0xffff;
                    b += l >>> 16;
                    c += h & 0xffff;
                    d += h >>> 16;

                    // Ch
                    h = ah4 & ah5 ^ ~ah4 & ah6;
                    l = al4 & al5 ^ ~al4 & al6;

                    a += l & 0xffff;
                    b += l >>> 16;
                    c += h & 0xffff;
                    d += h >>> 16;

                    // K
                    h = K[ i * 2 ];
                    l = K[ i * 2 + 1 ];

                    a += l & 0xffff;
                    b += l >>> 16;
                    c += h & 0xffff;
                    d += h >>> 16;

                    // w
                    h = wh[ i % 16 ];
                    l = wl[ i % 16 ];

                    a += l & 0xffff;
                    b += l >>> 16;
                    c += h & 0xffff;
                    d += h >>> 16;

                    b += a >>> 16;
                    c += b >>> 16;
                    d += c >>> 16;

                    th = c & 0xffff | d << 16;
                    tl = a & 0xffff | b << 16;

                    // add
                    h = th;
                    l = tl;

                    a = l & 0xffff;
                    b = l >>> 16;
                    c = h & 0xffff;
                    d = h >>> 16;

                    // Sigma0
                    h = ( ah0 >>> 28 | al0 << 32 - 28 ) ^ ( al0 >>> 34 - 32 | ah0 << 32 - ( 34 - 32 ) ) ^
                        ( al0 >>> 39 - 32 | ah0 << 32 - ( 39 - 32 ) );
                    l = ( al0 >>> 28 | ah0 << 32 - 28 ) ^ ( ah0 >>> 34 - 32 | al0 << 32 - ( 34 - 32 ) ) ^
                        ( ah0 >>> 39 - 32 | al0 << 32 - ( 39 - 32 ) );

                    a += l & 0xffff;
                    b += l >>> 16;
                    c += h & 0xffff;
                    d += h >>> 16;

                    // Maj
                    h = ah0 & ah1 ^ ah0 & ah2 ^ ah1 & ah2;
                    l = al0 & al1 ^ al0 & al2 ^ al1 & al2;

                    a += l & 0xffff;
                    b += l >>> 16;
                    c += h & 0xffff;
                    d += h >>> 16;

                    b += a >>> 16;
                    c += b >>> 16;
                    d += c >>> 16;

                    bh7 = c & 0xffff | d << 16;
                    bl7 = a & 0xffff | b << 16;

                    // add
                    h = bh3;
                    l = bl3;

                    a = l & 0xffff;
                    b = l >>> 16;
                    c = h & 0xffff;
                    d = h >>> 16;

                    h = th;
                    l = tl;

                    a += l & 0xffff;
                    b += l >>> 16;
                    c += h & 0xffff;
                    d += h >>> 16;

                    b += a >>> 16;
                    c += b >>> 16;
                    d += c >>> 16;

                    bh3 = c & 0xffff | d << 16;
                    bl3 = a & 0xffff | b << 16;

                    ah1 = bh0;
                    ah2 = bh1;
                    ah3 = bh2;
                    ah4 = bh3;
                    ah5 = bh4;
                    ah6 = bh5;
                    ah7 = bh6;
                    ah0 = bh7;

                    al1 = bl0;
                    al2 = bl1;
                    al3 = bl2;
                    al4 = bl3;
                    al5 = bl4;
                    al6 = bl5;
                    al7 = bl6;
                    al0 = bl7;

                    if ( i % 16 === 15 ) {
                        for ( j = 0; j < 16; j++ ) {
                            // add
                            h = wh[ j ];
                            l = wl[ j ];

                            a = l & 0xffff;
                            b = l >>> 16;
                            c = h & 0xffff;
                            d = h >>> 16;

                            h = wh[ ( j + 9 ) % 16 ];
                            l = wl[ ( j + 9 ) % 16 ];

                            a += l & 0xffff;
                            b += l >>> 16;
                            c += h & 0xffff;
                            d += h >>> 16;

                            // sigma0
                            th = wh[ ( j + 1 ) % 16 ];
                            tl = wl[ ( j + 1 ) % 16 ];
                            h = ( th >>> 1 | tl << 32 - 1 ) ^ ( th >>> 8 | tl << 32 - 8 ) ^ th >>> 7;
                            l = ( tl >>> 1 | th << 32 - 1 ) ^ ( tl >>> 8 | th << 32 - 8 ) ^ ( tl >>> 7 | th << 32 - 7 );

                            a += l & 0xffff;
                            b += l >>> 16;
                            c += h & 0xffff;
                            d += h >>> 16;

                            // sigma1
                            th = wh[ ( j + 14 ) % 16 ];
                            tl = wl[ ( j + 14 ) % 16 ];
                            h = ( th >>> 19 | tl << 32 - 19 ) ^ ( tl >>> 61 - 32 | th << 32 - ( 61 - 32 ) ) ^ th >>> 6;
                            l = ( tl >>> 19 | th << 32 - 19 ) ^ ( th >>> 61 - 32 | tl << 32 - ( 61 - 32 ) ) ^
                                ( tl >>> 6 | th << 26 );

                            a += l & 0xffff;
                            b += l >>> 16;
                            c += h & 0xffff;
                            d += h >>> 16;

                            b += a >>> 16;
                            c += b >>> 16;
                            d += c >>> 16;

                            wh[ j ] = c & 0xffff | d << 16;
                            wl[ j ] = a & 0xffff | b << 16;
                        }
                    }
                }

                // add
                h = ah0;
                l = al0;

                a = l & 0xffff;
                b = l >>> 16;
                c = h & 0xffff;
                d = h >>> 16;

                h = hh[ 0 ];
                l = hl[ 0 ];

                a += l & 0xffff;
                b += l >>> 16;
                c += h & 0xffff;
                d += h >>> 16;

                b += a >>> 16;
                c += b >>> 16;
                d += c >>> 16;

                hh[ 0 ] = ah0 = c & 0xffff | d << 16;
                hl[ 0 ] = al0 = a & 0xffff | b << 16;

                h = ah1;
                l = al1;

                a = l & 0xffff;
                b = l >>> 16;
                c = h & 0xffff;
                d = h >>> 16;

                h = hh[ 1 ];
                l = hl[ 1 ];

                a += l & 0xffff;
                b += l >>> 16;
                c += h & 0xffff;
                d += h >>> 16;

                b += a >>> 16;
                c += b >>> 16;
                d += c >>> 16;

                hh[ 1 ] = ah1 = c & 0xffff | d << 16;
                hl[ 1 ] = al1 = a & 0xffff | b << 16;

                h = ah2;
                l = al2;

                a = l & 0xffff;
                b = l >>> 16;
                c = h & 0xffff;
                d = h >>> 16;

                h = hh[ 2 ];
                l = hl[ 2 ];

                a += l & 0xffff;
                b += l >>> 16;
                c += h & 0xffff;
                d += h >>> 16;

                b += a >>> 16;
                c += b >>> 16;
                d += c >>> 16;

                hh[ 2 ] = ah2 = c & 0xffff | d << 16;
                hl[ 2 ] = al2 = a & 0xffff | b << 16;

                h = ah3;
                l = al3;

                a = l & 0xffff;
                b = l >>> 16;
                c = h & 0xffff;
                d = h >>> 16;

                h = hh[ 3 ];
                l = hl[ 3 ];

                a += l & 0xffff;
                b += l >>> 16;
                c += h & 0xffff;
                d += h >>> 16;

                b += a >>> 16;
                c += b >>> 16;
                d += c >>> 16;

                hh[ 3 ] = ah3 = c & 0xffff | d << 16;
                hl[ 3 ] = al3 = a & 0xffff | b << 16;

                h = ah4;
                l = al4;

                a = l & 0xffff;
                b = l >>> 16;
                c = h & 0xffff;
                d = h >>> 16;

                h = hh[ 4 ];
                l = hl[ 4 ];

                a += l & 0xffff;
                b += l >>> 16;
                c += h & 0xffff;
                d += h >>> 16;

                b += a >>> 16;
                c += b >>> 16;
                d += c >>> 16;

                hh[ 4 ] = ah4 = c & 0xffff | d << 16;
                hl[ 4 ] = al4 = a & 0xffff | b << 16;

                h = ah5;
                l = al5;

                a = l & 0xffff;
                b = l >>> 16;
                c = h & 0xffff;
                d = h >>> 16;

                h = hh[ 5 ];
                l = hl[ 5 ];

                a += l & 0xffff;
                b += l >>> 16;
                c += h & 0xffff;
                d += h >>> 16;

                b += a >>> 16;
                c += b >>> 16;
                d += c >>> 16;

                hh[ 5 ] = ah5 = c & 0xffff | d << 16;
                hl[ 5 ] = al5 = a & 0xffff | b << 16;

                h = ah6;
                l = al6;

                a = l & 0xffff;
                b = l >>> 16;
                c = h & 0xffff;
                d = h >>> 16;

                h = hh[ 6 ];
                l = hl[ 6 ];

                a += l & 0xffff;
                b += l >>> 16;
                c += h & 0xffff;
                d += h >>> 16;

                b += a >>> 16;
                c += b >>> 16;
                d += c >>> 16;

                hh[ 6 ] = ah6 = c & 0xffff | d << 16;
                hl[ 6 ] = al6 = a & 0xffff | b << 16;

                h = ah7;
                l = al7;

                a = l & 0xffff;
                b = l >>> 16;
                c = h & 0xffff;
                d = h >>> 16;

                h = hh[ 7 ];
                l = hl[ 7 ];

                a += l & 0xffff;
                b += l >>> 16;
                c += h & 0xffff;
                d += h >>> 16;

                b += a >>> 16;
                c += b >>> 16;
                d += c >>> 16;

                hh[ 7 ] = ah7 = c & 0xffff | d << 16;
                hl[ 7 ] = al7 = a & 0xffff | b << 16;

                pos += 128;
                n -= 128;
            }

            return n;
        }

        const hh = new Int32Array( 8 ),
            hl = new Int32Array( 8 ),
            x = new Uint8Array( 256 );
        let i;
        const b = n;

        hh[ 0 ] = 0x6a09e667;
        hh[ 1 ] = 0xbb67ae85;
        hh[ 2 ] = 0x3c6ef372;
        hh[ 3 ] = 0xa54ff53a;
        hh[ 4 ] = 0x510e527f;
        hh[ 5 ] = 0x9b05688c;
        hh[ 6 ] = 0x1f83d9ab;
        hh[ 7 ] = 0x5be0cd19;

        hl[ 0 ] = 0xf3bcc908;
        hl[ 1 ] = 0x84caa73b;
        hl[ 2 ] = 0xfe94f82b;
        hl[ 3 ] = 0x5f1d36f1;
        hl[ 4 ] = 0xade682d1;
        hl[ 5 ] = 0x2b3e6c1f;
        hl[ 6 ] = 0xfb41bd6b;
        hl[ 7 ] = 0x137e2179;

        crypto_hashblocks_hl( hh, hl, m, n );
        n %= 128;

        for ( i = 0; i < n; i++ ) x[ i ] = m[ b - n + i ];
        x[ n ] = 128;

        n = 256 - 128 * ( n < 112 ? 1 : 0 );
        x[ n - 9 ] = 0;
        ts64( x, n - 8, b / 0x20000000 | 0, b << 3 );
        crypto_hashblocks_hl( hh, hl, x, n );

        for ( i = 0; i < 8; i++ )
            ts64( out, 8 * i, hh[ i ], hl[ i ] );

        return 0;
    }

    static add( p, q ) {
        const a = curve25519.init_25519_constants(), b = curve25519.init_25519_constants(),
            c = curve25519.init_25519_constants(), d = curve25519.init_25519_constants(),
            e = curve25519.init_25519_constants(), f = curve25519.init_25519_constants(),
            g = curve25519.init_25519_constants(), h = curve25519.init_25519_constants(),
            t = curve25519.init_25519_constants();

        curve25519.blocksub( a, p[ 1 ], p[ 0 ] );
        curve25519.blocksub( t, q[ 1 ], q[ 0 ] );
        curve25519.blockround( a, a, t );
        curve25519.blockadd( b, p[ 0 ], p[ 1 ] );
        curve25519.blockadd( t, q[ 0 ], q[ 1 ] );
        curve25519.blockround( b, b, t );
        curve25519.blockround( c, p[ 3 ], q[ 3 ] );
        curve25519.blockround( c, c, curve25519.D2() );
        curve25519.blockround( d, p[ 2 ], q[ 2 ] );
        curve25519.blockadd( d, d, d );
        curve25519.blocksub( e, b, a );
        curve25519.blocksub( f, d, c );
        curve25519.blockadd( g, d, c );
        curve25519.blockadd( h, b, a );

        curve25519.blockround( p[ 0 ], e, f );
        curve25519.blockround( p[ 1 ], h, g );
        curve25519.blockround( p[ 2 ], g, f );
        curve25519.blockround( p[ 3 ], e, h );
    }

    static pack( r, p ) {
        const tx = curve25519.init_25519_constants(), ty = curve25519.init_25519_constants(),
            zi = curve25519.init_25519_constants();
        curve25519.inv25519( zi, p[ 2 ] );
        curve25519.blockround( tx, p[ 0 ], zi );
        curve25519.blockround( ty, p[ 1 ], zi );
        curve25519.pack25519( r, ty );
        r[ 31 ] ^= curve25519.par25519( tx ) << 7;
    }

    static scalarmult( p, q, s ) {
        function cswap( p, q, b ) {
            let i;
            for ( i = 0; i < 4; i++ ) {
                curve25519.sel25519( p[ i ], q[ i ], b );
            }
        }

        let b, i;
        curve25519.set25519( p[ 0 ], curve25519.gf0() );
        curve25519.set25519( p[ 1 ], curve25519.gf1() );
        curve25519.set25519( p[ 2 ], curve25519.gf1() );
        curve25519.set25519( p[ 3 ], curve25519.gf0() );
        for ( i = 255; i >= 0; --i ) {
            b = s[ ( i / 8 ) | 0 ] >> ( i & 7 ) & 1;
            cswap( p, q, b );
            add( q, p );
            add( p, p );
            cswap( p, q, b );
        }
    }

    static scalarbase( p, s ) {
        const q = [
            curve25519.init_25519_constants(),
            curve25519.init_25519_constants(),
            curve25519.init_25519_constants(),
            curve25519.init_25519_constants()
        ];
        curve25519.set25519( q[ 0 ], curve25519.X() );
        curve25519.set25519( q[ 1 ], curve25519.Y() );
        curve25519.set25519( q[ 2 ], curve25519.gf1() );
        curve25519.blockround( q[ 3 ], curve25519.X(), curve25519.Y() );
        curve25519.scalarmult( p, q, s );
    }

    static modL( r, x ) {
        const L = new Float64Array(
            [
                0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
            ]
        );

        let carry, i, j, k;
        for ( i = 63; i >= 32; --i ) {
            carry = 0;
            for ( j = i - 32, k = i - 12; j < k; ++j ) {
                x[ j ] += carry - 16 * x[ i ] * L[ j - ( i - 32 ) ];
                carry = x[ j ] + 128 >> 8;
                x[ j ] -= carry * 256;
            }
            x[ j ] += carry;
            x[ i ] = 0;
        }
        carry = 0;
        for ( j = 0; j < 32; j++ ) {
            x[ j ] += carry - ( x[ 31 ] >> 4 ) * L[ j ];
            carry = x[ j ] >> 8;
            x[ j ] &= 255;
        }
        for ( j = 0; j < 32; j++ ) x[ j ] -= carry * L[ j ];
        for ( i = 0; i < 32; i++ ) {
            x[ i + 1 ] += x[ i ] >> 8;
            r[ i ] = x[ i ] & 255;
        }
    }

    static reduce( r ) {
        const x = new Float64Array( 64 );
        let i;
        for ( i = 0; i < 64; i++ ) x[ i ] = r[ i ];
        for ( i = 0; i < 64; i++ ) r[ i ] = 0;
        curve25519.modL( r, x );
    }

    static curve25519_sign( sm, m, n, sk, opt_rnd ) {
        // Like crypto_sign, but uses secret key directly in hash.
        function crypto_sign_direct( sm, m, n, sk ) {
            const h = new Uint8Array( 64 ), r = new Uint8Array( 64 );
            let i, j;
            const x = new Float64Array( 64 );
            const p = [
                curve25519.init_25519_constants(),
                curve25519.init_25519_constants(),
                curve25519.init_25519_constants(),
                curve25519.init_25519_constants()
            ];

            for ( i = 0; i < n; i++ ) sm[ 64 + i ] = m[ i ];
            for ( i = 0; i < 32; i++ ) sm[ 32 + i ] = sk[ i ];

            curve25519.crypto_hash( r, sm.subarray( 32 ), n + 32 );
            curve25519.reduce( r );
            curve25519.scalarbase( p, r );
            curve25519.pack( sm, p );

            for ( i = 0; i < 32; i++ ) sm[ i + 32 ] = sk[ 32 + i ];
            curve25519.crypto_hash( h, sm, n + 64 );
            curve25519.reduce( h );

            for ( i = 0; i < 64; i++ ) x[ i ] = 0;
            for ( i = 0; i < 32; i++ ) x[ i ] = r[ i ];
            for ( i = 0; i < 32; i++ ) {
                for ( j = 0; j < 32; j++ ) {
                    x[ i + j ] += h[ i ] * sk[ j ];
                }
            }

            curve25519.modL( sm.subarray( 32 ), x );
            return n + 64;
        }

        // Note: sm must be n+128.
        function crypto_sign_direct_rnd( sm, m, n, sk, rnd ) {
            const h = new Uint8Array( 64 ), r = new Uint8Array( 64 );
            let i, j;
            const x = new Float64Array( 64 );
            const p = [
                curve25519.init_25519_constants(),
                curve25519.init_25519_constants(),
                curve25519.init_25519_constants(),
                curve25519.init_25519_constants()
            ];

            // Hash separation.
            sm[ 0 ] = 0xfe;
            for ( i = 1; i < 32; i++ ) sm[ i ] = 0xff;

            // Secret key.
            for ( i = 0; i < 32; i++ ) sm[ 32 + i ] = sk[ i ];

            // Message.
            for ( i = 0; i < n; i++ ) sm[ 64 + i ] = m[ i ];

            // Random suffix.
            for ( i = 0; i < 64; i++ ) sm[ n + 64 + i ] = rnd[ i ];

            curve25519.crypto_hash( r, sm, n + 128 );
            curve25519.reduce( r );
            curve25519.scalarbase( p, r );
            curve25519.pack( sm, p );

            for ( i = 0; i < 32; i++ ) sm[ i + 32 ] = sk[ 32 + i ];
            curve25519.crypto_hash( h, sm, n + 64 );
            curve25519.reduce( h );

            // Wipe out random suffix.
            for ( i = 0; i < 64; i++ ) sm[ n + 64 + i ] = 0;

            for ( i = 0; i < 64; i++ ) x[ i ] = 0;
            for ( i = 0; i < 32; i++ ) x[ i ] = r[ i ];
            for ( i = 0; i < 32; i++ ) {
                for ( j = 0; j < 32; j++ ) {
                    x[ i + j ] += h[ i ] * sk[ j ];
                }
            }

            curve25519.modL( sm.subarray( 32, n + 64 ), x );

            return n + 64;
        }

        // If opt_rnd is provided, sm must have n + 128,
        // otherwise it must have n + 64 bytes.

        // Convert Curve25519 secret key into Ed25519 secret key (includes pub key).
        const edsk = new Uint8Array( 64 );
        const p = [
            curve25519.init_25519_constants(),
            curve25519.init_25519_constants(),
            curve25519.init_25519_constants(),
            curve25519.init_25519_constants()
        ];

        for ( let i = 0; i < 32; i++ ) edsk[ i ] = sk[ i ];
        // Ensure private key is in the correct format.
        edsk[ 0 ] &= 248;
        edsk[ 31 ] &= 127;
        edsk[ 31 ] |= 64;

        curve25519.scalarbase( p, edsk );
        curve25519.pack( edsk.subarray( 32 ), p );

        // Remember sign bit.
        const signBit = edsk[ 63 ] & 128;
        let smlen;

        if ( opt_rnd ) {
            smlen = crypto_sign_direct_rnd( sm, m, n, edsk, opt_rnd );
        } else {
            smlen = crypto_sign_direct( sm, m, n, edsk );
        }

        // Copy sign bit from public key into signature.
        sm[ 63 ] |= signBit;
        return smlen;
    }

    // Converts Curve25519 public key back to Ed25519 public key.
    // edwardsY = (montgomeryX - 1) / (montgomeryX + 1)
    static convertPublicKey( pk ) {
        const z = new Uint8Array( 32 ),
            x = curve25519.init_25519_constants(), a = curve25519.init_25519_constants(),
            b = curve25519.init_25519_constants();

        curve25519.unpack25519( x, pk );

        curve25519.blockadd( a, x, curve25519.gf1() );
        curve25519.blocksub( b, x, curve25519.gf1() );
        curve25519.inv25519( a, a );
        curve25519.blockround( a, a, b );

        curve25519.pack25519( z, a );
        return z;
    }

    static curve25519_sign_open( m, sm, n, pk ) {
        function crypto_sign_open( m, sm, n, pk ) {
            function unpackneg( r, p ) {
                function neq25519( a, b ) {
                    const c = new Uint8Array( 32 ), d = new Uint8Array( 32 );
                    curve25519.pack25519( c, a );
                    curve25519.pack25519( d, b );
                    return curve25519.crypto_verify_32( c, 0, d, 0 );
                }

                function pow2523( o, i ) {
                    const c = curve25519.init_25519_constants();
                    let a;
                    for ( a = 0; a < 16; a++ ) c[ a ] = i[ a ];
                    for ( a = 250; a >= 0; a-- ) {
                        curve25519.blockround_dest( c, c );
                        if ( a !== 1 ) curve25519.blockround( c, c, i );
                    }
                    for ( a = 0; a < 16; a++ ) o[ a ] = c[ a ];
                }

                const t = curve25519.init_25519_constants(), chk = curve25519.init_25519_constants(),
                    num = curve25519.init_25519_constants(), den = curve25519.init_25519_constants(),
                    den2 = curve25519.init_25519_constants(), den4 = curve25519.init_25519_constants(),
                    den6 = curve25519.init_25519_constants();

                curve25519.set25519( r[ 2 ], curve25519.gf1() );
                curve25519.unpack25519( r[ 1 ], p );
                curve25519.blockround_dest( num, r[ 1 ] );
                curve25519.blockround( den, num, curve25519.D() );
                curve25519.blocksub( num, num, r[ 2 ] );
                curve25519.blockadd( den, r[ 2 ], den );

                curve25519.blockround_dest( den2, den );
                curve25519.blockround_dest( den4, den2 );
                curve25519.blockround( den6, den4, den2 );
                curve25519.blockround( t, den6, num );
                curve25519.blockround( t, t, den );

                pow2523( t, t );
                curve25519.blockround( t, t, num );
                curve25519.blockround( t, t, den );
                curve25519.blockround( t, t, den );
                curve25519.blockround( r[ 0 ], t, den );

                curve25519.blockround_dest( chk, r[ 0 ] );
                curve25519.blockround( chk, chk, den );
                if ( neq25519( chk, num ) ) curve25519.blockround( r[ 0 ], r[ 0 ], curve25519.I() );

                curve25519.blockround_dest( chk, r[ 0 ] );
                curve25519.blockround( chk, chk, den );
                if ( neq25519( chk, num ) ) return -1;

                if ( curve25519.par25519( r[ 0 ] ) === p[ 31 ] >> 7 )
                    curve25519.blocksub( r[ 0 ], curve25519.gf0(), r[ 0 ] );

                curve25519.blockround( r[ 3 ], r[ 0 ], r[ 1 ] );
                return 0;
            }

            let i, mlen;
            const t = new Uint8Array( 32 ), h = new Uint8Array( 64 );
            const p = [
                    curve25519.init_25519_constants(),
                    curve25519.init_25519_constants(),
                    curve25519.init_25519_constants(),
                    curve25519.init_25519_constants()
                ],
                q = [
                    curve25519.init_25519_constants(),
                    curve25519.init_25519_constants(),
                    curve25519.init_25519_constants(),
                    curve25519.init_25519_constants()
                ];

            if ( n < 64 ) return -1;

            if ( unpackneg( q, pk ) ) return -1;

            for ( i = 0; i < n; i++ ) m[ i ] = sm[ i ];
            for ( i = 0; i < 32; i++ ) m[ i + 32 ] = pk[ i ];
            curve25519.crypto_hash( h, m, n );
            curve25519.reduce( h );
            curve25519.scalarmult( p, q, h );

            curve25519.scalarbase( q, sm.subarray( 32 ) );
            add( p, q );
            curve25519.pack( t, p );

            n -= 64;
            if ( curve25519.crypto_verify_32( sm, 0, t, 0 ) ) {
                for ( i = 0; i < n; i++ ) m[ i ] = 0;
                return -1;
            }

            for ( i = 0; i < n; i++ ) m[ i ] = sm[ i + 64 ];
            mlen = n;
            return mlen;
        }

        // Convert Curve25519 public key into Ed25519 public key.
        const edpk = curve25519.convertPublicKey( pk );

        // Restore sign bit from signature.
        edpk[ 31 ] |= sm[ 63 ] & 128;

        // Remove sign bit from signature.
        sm[ 63 ] &= 127;

        // Verify signed message.
        return crypto_sign_open( m, sm, n, edpk );
    }

    static sharedKey( secretKey, publicKey ) {

        curve25519.checkArrayTypes( publicKey, secretKey );

        if ( publicKey.length !== 32 )
            throw new Error( 'wrong public key length' );

        if ( secretKey.length !== 32 )
            throw new Error( 'wrong secret key length' );

        const sharedKey = new Uint8Array( 32 );

        curve25519.crypto_scalarmult( sharedKey, secretKey, publicKey );

        return sharedKey;
    }

    static signMessage( secretKey, msg, opt_random ) {

        curve25519.checkArrayTypes( msg, secretKey );

        if ( secretKey.length !== 32 )
            throw new Error( 'wrong secret key length' );

        if ( opt_random ) {
            curve25519.checkArrayTypes( opt_random );

            if ( opt_random.length !== 64 )
                throw new Error( 'wrong random data length' );

            const buf = new Uint8Array( 128 + msg.length );

            curve25519.curve25519_sign( buf, msg, msg.length, secretKey, opt_random );

            return new Uint8Array( buf.subarray( 0, 64 + msg.length ) );

        } else {
            const signedMsg = new Uint8Array( 64 + msg.length );

            curve25519.curve25519_sign( signedMsg, msg, msg.length, secretKey );

            return signedMsg;
        }
    }

    static openMessage( publicKey, signedMsg ) {

        curve25519.checkArrayTypes( signedMsg, publicKey );

        if ( publicKey.length !== 32 )
            throw new Error( 'wrong public key length' );

        const tmp = new Uint8Array( signedMsg.length );

        const len = curve25519.curve25519_sign_open( tmp, signedMsg, signedMsg.length, publicKey );

        if ( len < 0 )
            return null;

        const m = new Uint8Array( len );

        for ( let i = 0; i < m.length; i++ )
            m[ i ] = tmp[ i ];

        return m;
    }

    static sign( secretKey, msg, opt_random ) {
        curve25519.checkArrayTypes( secretKey, msg );

        if ( secretKey.length !== 32 )
            throw new Error( 'wrong secret key length' );

        if ( opt_random ) {
            curve25519.checkArrayTypes( opt_random );

            if ( opt_random.length !== 64 )
                throw new Error( 'wrong random data length' );
        }

        const buf = new Uint8Array( ( opt_random ? 128 : 64 ) + msg.length );

        curve25519.curve25519_sign( buf, msg, msg.length, secretKey, opt_random );

        const signature = new Uint8Array( 64 );

        for ( let i = 0; i < signature.length; i++ )
            signature[ i ] = buf[ i ];

        return signature;
    }

    static verify( publicKey, msg, signature ) {
        curve25519.checkArrayTypes( msg, signature, publicKey );

        if ( signature.length !== 64 )
            throw new Error( 'wrong signature length' );

        if ( publicKey.length !== 32 )
            throw new Error( 'wrong public key length' );

        const sm = new Uint8Array( 64 + msg.length );
        const m = new Uint8Array( 64 + msg.length );

        for ( let i = 0; i < 64; i++ )
            sm[ i ] = signature[ i ];

        for ( let i = 0; i < msg.length; i++ )
            sm[ i + 64 ] = msg[ i ];

        return curve25519.curve25519_sign_open( m, sm, sm.length, publicKey ) >= 0;
    }

    static generateKeyPair( seed ) {
        function crypto_scalarmult_base( q, n ) {
            const _9 = new Uint8Array( 32 );
            _9[ 0 ] = 9;

            return curve25519.crypto_scalarmult( q, n, _9 );
        }

        curve25519.checkArrayTypes( seed );

        if ( seed.length !== 32 )
            throw new Error( 'wrong seed length' );

        const sk = new Uint8Array( 32 );
        const pk = new Uint8Array( 32 );

        for ( let i = 0; i < 32; i++ )
            sk[ i ] = seed[ i ];

        crypto_scalarmult_base( pk, sk );

        // Turn secret key into the correct format.
        sk[ 0 ] &= 248;
        sk[ 31 ] &= 127;
        sk[ 31 ] |= 64;

        // Remove sign bit from public key.
        pk[ 31 ] &= 127;

        return {
            public: pk,
            private: sk
        };
    }
}
