/**
 * XOR tests
 *
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2016
 * @license Apache-2.0
 */
import TestRegister from "../../lib/TestRegister.mjs";

const STANDARD_ARGS = [{ "option": "Hex", "string": "fe" }, "Standard", false, "8-bit", "Little Endian", 0];
const LEGACY_ARGS = [{ "option": "Hex", "string": "fe" }, "Standard", false];
const ROLL_8_INC1 = [{ "option": "Hex", "string": "50" }, "Rolling increment", false, "8-bit", "Little Endian", 1];
const ROLL_8_INC2 = [{ "option": "Hex", "string": "50" }, "Rolling increment", false, "8-bit", "Little Endian", 2];
const ADD_PT_8 = [{ "option": "Hex", "string": "0a" }, "Rolling add plaintext", false, "8-bit", "Little Endian", 0];
const ADD_CT_8 = [{ "option": "Hex", "string": "0a" }, "Rolling add ciphertext", false, "8-bit", "Little Endian", 0];

TestRegister.addTests([
    {
        name: "XOR: Standard",
        input: "fe023da5",
        expectedOutput: "00fcc35b",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": STANDARD_ARGS },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Standard with legacy 3-arg recipe",
        input: "fe023da5",
        expectedOutput: "00fcc35b",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": LEGACY_ARGS },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Input differential",
        input: "010203",
        expectedOutput: "010301",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "00" }, "Input differential", false, "8-bit", "Little Endian", 0] },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Output differential",
        input: "010203",
        expectedOutput: "010300",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "00" }, "Output differential", false, "8-bit", "Little Endian", 0] },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Cascade",
        input: "010203",
        expectedOutput: "030103",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "00" }, "Cascade", false, "8-bit", "Little Endian", 0] },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling increment (8-bit, increment 1)",
        input: "41424344",
        expectedOutput: "11131117",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": ROLL_8_INC1 },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling increment (8-bit, increment 2)",
        input: "4142",
        expectedOutput: "1110",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": ROLL_8_INC2 },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling increment (16-bit little endian)",
        input: "02000300",
        expectedOutput: "03000100",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "0001" }, "Rolling increment", false, "16-bit", "Little Endian", 1] },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling increment (32-bit little endian)",
        input: "0200000003000000",
        expectedOutput: "0300000001000000",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "00000001" }, "Rolling increment", false, "32-bit", "Little Endian", 1] },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling increment (32-bit big endian)",
        input: "0000000200000003",
        expectedOutput: "0000000300000001",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "00000001" }, "Rolling increment", false, "32-bit", "Big Endian", 1] },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling increment (64-bit little endian)",
        input: "0200000000000000",
        expectedOutput: "0300000000000000",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "0000000000000001" }, "Rolling increment", false, "64-bit", "Little Endian", 1] },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling add plaintext (8-bit)",
        input: "010203",
        expectedOutput: "0b090e",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": ADD_PT_8 },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling add plaintext (32-bit little endian)",
        input: "0500000008000000",
        expectedOutput: "040000000e000000",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "00000001" }, "Rolling add plaintext", false, "32-bit", "Little Endian", 0] },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling add ciphertext (8-bit)",
        input: "010203",
        expectedOutput: "0b172f",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": ADD_CT_8 },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling add ciphertext (32-bit little endian)",
        input: "0500000008000000",
        expectedOutput: "040000000d000000",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "00000001" }, "Rolling add ciphertext", false, "32-bit", "Little Endian", 0] },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling increment handles uint32 wraparound",
        input: "0000000001000000",
        expectedOutput: "ffffffff01000000",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "ffffffff" }, "Rolling increment", false, "32-bit", "Little Endian", 1] },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling add plaintext handles uint32 wraparound",
        input: "0200000000000000",
        expectedOutput: "fdffffff01000000",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "ffffffff" }, "Rolling add plaintext", false, "32-bit", "Little Endian", 0] },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling increment roundtrip",
        input: "4142434445",
        expectedOutput: "4142434445",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": ROLL_8_INC2 },
            { "op": "XOR", "args": ROLL_8_INC2 },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling add plaintext roundtrip (32-bit little endian, single block)",
        input: "00000005",
        expectedOutput: "00000005",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "00000001" }, "Rolling add plaintext", false, "32-bit", "Little Endian", 0] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "00000001" }, "Rolling add plaintext", false, "32-bit", "Little Endian", 0] },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling add ciphertext roundtrip (32-bit little endian, single block)",
        input: "00000005",
        expectedOutput: "00000005",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "00000001" }, "Rolling add ciphertext", false, "32-bit", "Little Endian", 0] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "00000001" }, "Rolling add ciphertext", false, "32-bit", "Little Endian", 0] },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling increment roundtrip (64-bit little endian)",
        input: "0300000000000000",
        expectedOutput: "0300000000000000",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "0000000000000001" }, "Rolling increment", false, "64-bit", "Little Endian", 1] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "0000000000000001" }, "Rolling increment", false, "64-bit", "Little Endian", 1] },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling add plaintext encode (32-bit little endian)",
        input: "31c0506a016a0289e1b06631dbb301cd8089c683c40c31c0505068c0a800016668115c666a0289e16a10515689e1b066b303cd8083c41c89f3b006cd8031dbb001cd8090",
        expectedOutput: "2e9d93cd5177169bb03770aae98b7c018d65b81a497974dd01d21e1d09d2dffb21c28365dbe6b28b71f7951d0c16a5c4bdda0b8842188f00b711b6dfb7636c6fb64e1200",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "a7c35d1f" }, "Rolling add plaintext", false, "32-bit", "Little Endian", 0] },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling add plaintext decode (32-bit little endian)",
        input: "2e9d93cd5177169bb03770aae98b7c018d65b81a497974dd01d21e1d09d2dffb21c28365dbe6b28b71f7951d0c16a5c4bdda0b8842188f00b711b6dfb7636c6fb64e1200",
        expectedOutput: "31c0506a016a0289e1b06631dbb301cd8089c683c40c31c0505068c0a800016668115c666a0289e16a10515689e1b066b303cd8083c41c89f3b006cd8031dbb001cd8090",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "a7c35d1f" }, "Rolling add plaintext", false, "32-bit", "Little Endian", 0, "Decode"] },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling add plaintext roundtrip across many blocks (32-bit little endian, Encode then Decode)",
        input: "31c0506a016a0289e1b06631dbb301cd8089c683c40c31c0505068c0a800016668115c666a0289e16a10515689e1b066b303cd8083c41c89f3b006cd8031dbb001cd8090",
        expectedOutput: "31c0506a016a0289e1b06631dbb301cd8089c683c40c31c0505068c0a800016668115c666a0289e16a10515689e1b066b303cd8083c41c89f3b006cd8031dbb001cd8090",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "a7c35d1f" }, "Rolling add plaintext", false, "32-bit", "Little Endian", 0, "Encode"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "a7c35d1f" }, "Rolling add plaintext", false, "32-bit", "Little Endian", 0, "Decode"] },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
    {
        name: "XOR: Rolling add ciphertext roundtrip across many blocks (32-bit little endian, Encode then Decode)",
        input: "01000000020000000300000004000000",
        expectedOutput: "01000000020000000300000004000000",
        recipeConfig: [
            { "op": "From Hex", "args": ["None"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "00000005" }, "Rolling add ciphertext", false, "32-bit", "Little Endian", 0, "Encode"] },
            { "op": "XOR", "args": [{ "option": "Hex", "string": "00000005" }, "Rolling add ciphertext", false, "32-bit", "Little Endian", 0, "Decode"] },
            { "op": "To Hex", "args": ["None"] }
        ]
    },
]);
