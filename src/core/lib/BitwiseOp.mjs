/**
 * Bitwise operation resources.
 *
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2018
 * @license Apache-2.0
 */
import OperationError from "../errors/OperationError.mjs";

/**
 * Runs bitwise operations across the input data.
 *
 * @param {byteArray|Uint8Array} input
 * @param {byteArray} key
 * @param {function} func - The bitwise calculation to carry out
 * @param {boolean} nullPreserving
 * @param {string} scheme - "Standard", "Input differential", "Output differential", "Cascade" or one of the rolling schemes
 * @param {number} [blockSizeBytes=1] - The block size in bytes used by the rolling schemes (1, 2, 4 or 8)
 * @param {string} [endianness="Little Endian"] - The byte order used to pack each block into an integer
 * @param {number} [incrementValue=0] - The number added to the key after each block by "Rolling increment"
 * @returns {byteArray}
 */
export function bitOp(input, key, func, nullPreserving, scheme, blockSizeBytes = 1, endianness = "Little Endian", incrementValue = 0) {
    if (!key || !key.length) key = [0];

    // The rolling schemes treat the key as a single unsigned integer of
    // blockSizeBytes bytes which evolves after each complete block
    if (scheme === "Rolling increment" ||
        scheme === "Rolling add plaintext" ||
        scheme === "Rolling add ciphertext") {
        if (!Number.isInteger(blockSizeBytes) || blockSizeBytes < 1 || blockSizeBytes > 8) {
            throw new OperationError("Invalid block size");
        }
        const littleEndian = endianness === "Little Endian",
            result = new Array(input.length),
            keyBytes = new Array(blockSizeBytes).fill(0),
            cipherBytes = new Array(blockSizeBytes);
        let r = 0;

        // The key is read as an unsigned integer, most significant byte first,
        // then serialised in the block's byte order. Its high-order bytes are
        // discarded if it is wider than the block size.
        if (key.length) {
            const len = Math.min(key.length, blockSizeBytes),
                offset = key.length - len;
            if (littleEndian) {
                for (let i = 0; i < len; i++) keyBytes[len - 1 - i] = key[offset + i];
            } else {
                for (let i = 0; i < len; i++) keyBytes[blockSizeBytes - len + i] = key[offset + i];
            }
        }

        let pos = 0;
        for (; pos + blockSizeBytes <= input.length; pos += blockSizeBytes) {
            for (let j = 0; j < blockSizeBytes; j++) {
                const o = input[pos + j],
                    x = func(o, keyBytes[j]);
                cipherBytes[j] = x;
                result[r++] = nullPreserving && (o === 0 || o === keyBytes[j]) ? o : x;
            }

            switch (scheme) {
                case "Rolling increment":
                    addToKeyBytes(keyBytes, incrementValue, littleEndian);
                    break;
                case "Rolling add plaintext":
                    addBytesToKeyBytes(keyBytes, input, pos, littleEndian);
                    break;
                case "Rolling add ciphertext":
                    addBytesToKeyBytes(keyBytes, cipherBytes, 0, littleEndian);
                    break;
            }
        }

        // Any trailing bytes are XORed against the current key without updating it
        for (let j = pos; j < input.length; j++) {
            const o = input[j],
                kb = keyBytes[j - pos];
            result[r++] = nullPreserving && (o === 0 || o === kb) ? o : func(o, kb);
        }

        return result;
    }

    const result = [];
    let x = null,
        k = null,
        o = null;

    for (let i = 0; i < input.length; i++) {
        k = key[i % key.length];
        if (scheme === "Cascade") k = input[i + 1] || 0;
        o = input[i];
        x = nullPreserving && (o === 0 || o === k) ? o : func(o, k);
        result.push(x);
        if (scheme &&
            scheme !== "Standard" &&
            !(nullPreserving && (o === 0 || o === k))) {
            switch (scheme) {
                case "Input differential":
                    key[i % key.length] = o;
                    break;
                case "Output differential":
                    key[i % key.length] = x;
                    break;
            }
        }
    }

    return result;
}

/**
 * Adds a value to the key byte array, propagating any carry in the chosen
 * byte order. Carry beyond the key length is discarded (modulo 2^bits).
 *
 * @param {byteArray} keyBytes
 * @param {number} value
 * @param {boolean} littleEndian
 */
function addToKeyBytes(keyBytes, value, littleEndian) {
    let carry = value;
    if (littleEndian) {
        for (let i = 0; i < keyBytes.length && carry > 0; i++) {
            const sum = keyBytes[i] + carry;
            keyBytes[i] = sum & 0xff;
            carry = Math.floor(sum / 256);
        }
    } else {
        for (let i = keyBytes.length - 1; i >= 0 && carry > 0; i--) {
            const sum = keyBytes[i] + carry;
            keyBytes[i] = sum & 0xff;
            carry = Math.floor(sum / 256);
        }
    }
}


/**
 * Adds a block of bytes to the key byte array, propagating any carry in the
 * chosen byte order. Carry beyond the key length is discarded (modulo 2^bits).
 *
 * @param {byteArray} keyBytes
 * @param {byteArray|Uint8Array} addend
 * @param {number} offset
 * @param {boolean} littleEndian
 */
function addBytesToKeyBytes(keyBytes, addend, offset, littleEndian) {
    let carry = 0;
    if (littleEndian) {
        for (let i = 0; i < keyBytes.length; i++) {
            const sum = keyBytes[i] + addend[offset + i] + carry;
            keyBytes[i] = sum & 0xff;
            carry = Math.floor(sum / 256);
        }
    } else {
        for (let i = keyBytes.length - 1; i >= 0; i--) {
            const sum = keyBytes[i] + addend[offset + i] + carry;
            keyBytes[i] = sum & 0xff;
            carry = Math.floor(sum / 256);
        }
    }
}


/**
 * XOR bitwise calculation.
 *
 * @param {number} operand
 * @param {number} key
 * @returns {number}
 */
export function xor(operand, key) {
    return operand ^ key;
}


/**
 * NOT bitwise calculation.
 *
 * @param {number} operand
 * @returns {number}
 */
export function not(operand, _) {
    return ~operand & 0xff;
}


/**
 * AND bitwise calculation.
 *
 * @param {number} operand
 * @param {number} key
 * @returns {number}
 */
export function and(operand, key) {
    return operand & key;
}


/**
 * OR bitwise calculation.
 *
 * @param {number} operand
 * @param {number} key
 * @returns {number}
 */
export function or(operand, key) {
    return operand | key;
}


/**
 * ADD bitwise calculation.
 *
 * @param {number} operand
 * @param {number} key
 * @returns {number}
 */
export function add(operand, key) {
    return (operand + key) % 256;
}


/**
 * SUB bitwise calculation.
 *
 * @param {number} operand
 * @param {number} key
 * @returns {number}
 */
export function sub(operand, key) {
    const result = operand - key;
    return (result < 0) ? 256 + result : result;
}


/**
 * Delimiter options for bitwise operations
 */
export const BITWISE_OP_DELIMS = ["Hex", "Decimal", "Binary", "Base64", "UTF8", "Latin1"];
