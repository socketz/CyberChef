/**
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2016
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import Utils from "../Utils.mjs";
import { bitOp, rollingXor, xor, BITWISE_OP_DELIMS } from "../lib/BitwiseOp.mjs";

/**
 * XOR operation
 */
class XOR extends Operation {

    /**
     * XOR constructor
     */
    constructor() {
        super();

        this.name = "XOR";
        this.module = "Default";
        this.description = "XOR the input with the given key.<br>e.g. <code>fe023da5</code><br><br><strong>Options</strong><br><u>Null preserving:</u> If the current byte is 0x00 or the same as the key, skip it.<br><br><u>Scheme:</u><ul><li>Standard - key is unchanged after each round</li><li>Input differential - key is set to the value of the previous unprocessed byte</li><li>Output differential - key is set to the value of the previous processed byte</li><li>Cascade - key is set to the input byte shifted by one</li></ul><br>The following rolling schemes treat the key as a single unsigned integer, <code>block size</code> bits wide, and process the input one block at a time:<ul><li>Rolling increment - the key is incremented by the Increment value after each block</li><li>Rolling add plaintext - the key is incremented by the value of the current plaintext block after each block</li><li>Rolling add ciphertext - the key is incremented by the value of the current ciphertext block after each block</li></ul>Any bytes remaining after the final complete block are XORed against the current key without updating it.<br><br><strong>Options for rolling schemes</strong><br><u>Block size:</u> The size of the blocks the input is split into and the width of the key integer (8, 16, 32 or 64 bits).<br><u>Endianness:</u> The byte order used to pack each block into an integer (only relevant for block sizes over 8-bit). The key is always read as an unsigned integer, most significant byte first.<br><u>Increment value:</u> The number added to the key after each block when using the Rolling increment scheme.";
        this.infoURL = "https://wikipedia.org/wiki/XOR";
        this.inputType = "ArrayBuffer";
        this.outputType = "byteArray";
        this.args = [
            {
                "name": "Key",
                "type": "toggleString",
                "value": "",
                "toggleValues": BITWISE_OP_DELIMS
            },
            {
                "name": "Scheme",
                "type": "option",
                "value": ["Standard", "Input differential", "Output differential", "Cascade", "Rolling increment", "Rolling add plaintext", "Rolling add ciphertext"]
            },
            {
                "name": "Null preserving",
                "type": "boolean",
                "value": false
            },
            {
                "name": "Block size",
                "type": "option",
                "value": ["8-bit", "16-bit", "32-bit", "64-bit"]
            },
            {
                "name": "Endianness",
                "type": "option",
                "value": ["Little Endian", "Big Endian"]
            },
            {
                "name": "Increment value",
                "type": "number",
                "value": 0,
                "min": 0,
                "integer": true,
                "allowEmpty": false
            }
        ];
    }

    /**
     * @param {ArrayBuffer} input
     * @param {Object[]} args
     * @returns {byteArray}
     */
    run(input, args) {
        input = new Uint8Array(input);
        const key = Utils.convertToByteArray(args[0].string || "", args[0].option),
            [, scheme, nullPreserving, blockSize = "8-bit", endianness = "Little Endian", incrementValue = 0] = args;

        if (scheme && scheme.startsWith("Rolling")) {
            const blockSizeBytes = parseInt(blockSize, 10) / 8;
            return rollingXor(input, key, scheme, nullPreserving, blockSizeBytes, endianness, incrementValue);
        }

        return bitOp(input, key, xor, nullPreserving, scheme);
    }

    /**
     * Highlight XOR
     *
     * @param {Object[]} pos
     * @param {number} pos[].start
     * @param {number} pos[].end
     * @param {Object[]} args
     * @returns {Object[]} pos
     */
    highlight(pos, args) {
        return pos;
    }

    /**
     * Highlight XOR in reverse
     *
     * @param {Object[]} pos
     * @param {number} pos[].start
     * @param {number} pos[].end
     * @param {Object[]} args
     * @returns {Object[]} pos
     */
    highlightReverse(pos, args) {
        return pos;
    }

}

export default XOR;
