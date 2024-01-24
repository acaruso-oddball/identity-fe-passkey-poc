"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.uint8ArrayToString = exports.uint8ArrayToBase64Url = void 0;
function uint8ArrayToBase64Url(uint8Array) {
    // Step 1: Convert Uint8Array to ArrayBuffer
    console.log("hjhdfs", uint8Array);
    const arrayBuffer = uint8Array.buffer.slice(uint8Array.byteOffset, uint8Array.byteOffset + uint8Array.byteLength);
    // Step 2: Use btoa to Base64 encode the ArrayBuffer
    const base64String = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
    // Step 3: Replace characters that are not URL-safe
    const base64Url = base64String
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    console.log("hhhh", base64String);
    return base64Url;
}
exports.uint8ArrayToBase64Url = uint8ArrayToBase64Url;
// // Example usage
// const uint8Array = new Uint8Array([72, 101, 108, 108, 111]); // Uint8Array representing 'Hello'
// const base64Url = uint8ArrayToBase64Url(uint8Array);
// console.log(base64Url); // Output: SGVsbG8
function uint8ArrayToString(uint8Array) {
    // Create a TextDecoder with the desired encoding (e.g., 'utf-8')
    const textDecoder = new TextDecoder('utf-8');
    // Decode the Uint8Array to a string
    const decodedString = textDecoder.decode(uint8Array);
    return decodedString;
}
exports.uint8ArrayToString = uint8ArrayToString;
//# sourceMappingURL=server-utils.js.map