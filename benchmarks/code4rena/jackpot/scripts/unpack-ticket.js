#!/usr/bin/env node

/**
 * Ticket Unpacker Script
 * 
 * This script helps decode packed ticket numbers from the Jackpot contract.
 * 
 * Usage:
 *   node unpack-ticket.js <packedTicket> <maxNormalBall>
 * 
 * Example:
 *   node unpack-ticket.js 123456789 30
 */

// Unpack function ported from protocolUtils.ts
function unpackTicket(packedTicket, maxNormalBall) {
    const balls = [];
    
    // Convert string inputs to BigInt
    const packed = BigInt(packedTicket);
    const maxNormal = BigInt(maxNormalBall);
    
    // Extract all numbers by checking each bit
    for (let i = 0; i < 256; i++) {
        const mask = 1n << BigInt(i);
        if ((packed & mask) !== 0n) {
            balls.push(BigInt(i));
        }
    }
    
    // Return ticket structure
    return {
        normals: balls.slice(0, -1).map(n => Number(n)),
        bonusball: Number(balls[balls.length - 1] - maxNormal)
    };
}

// Main execution
function main() {
    const args = process.argv.slice(2);
    
    if (args.length < 2) {
        console.log('❌ Missing required arguments');
        console.log('');
        console.log('Usage:');
        console.log('  node unpack-ticket.js <packedTicket> <maxNormalBall>');
        console.log('');
        console.log('Example:');
        console.log('  node unpack-ticket.js 123456789 30');
        console.log('');
        console.log('Where:');
        console.log('  - packedTicket: The packed ticket number from the contract');
        console.log('  - maxNormalBall: The maximum normal ball number for the drawing (usually 30)');
        process.exit(1);
    }
    
    const packedTicket = args[0];
    const maxNormalBall = args[1];
    
    try {
        console.log('🎫 Unpacking Ticket Numbers');
        console.log('==========================');
        console.log(`Packed Ticket: ${packedTicket}`);
        console.log(`Max Normal Ball: ${maxNormalBall}`);
        console.log('');
        
        const ticket = unpackTicket(packedTicket, maxNormalBall);
        
        console.log('📊 Unpacked Results:');
        console.log(`Normal Numbers: [${ticket.normals.join(', ')}]`);
        console.log(`Bonusball: ${ticket.bonusball}`);
        console.log('');
        
        // Validation
        if (ticket.normals.length !== 5) {
            console.log('⚠️  Warning: Expected 5 normal numbers, got', ticket.normals.length);
        }
        
        // Check for valid ranges
        const invalidNormals = ticket.normals.filter(n => n < 1 || n > maxNormalBall);
        if (invalidNormals.length > 0) {
            console.log('⚠️  Warning: Some normal numbers are out of range:', invalidNormals);
        }
        
        if (ticket.bonusball < 1) {
            console.log('⚠️  Warning: Bonusball number seems invalid:', ticket.bonusball);
        }
        
        console.log('✅ Unpacking complete!');
        
    } catch (error) {
        console.error('❌ Error unpacking ticket:', error.message);
        process.exit(1);
    }
}

// Helper function to get max normal ball from Etherscan
function printEtherscanHelp() {
    console.log('');
    console.log('💡 How to find maxNormalBall:');
    console.log('1. Go to: https://sepolia.basescan.org/address/0xDF61A9c7d6B35AA2C9eB4F919d46068E24bFAa3C');
    console.log('2. Click "Contract" → "Read Contract"');
    console.log('3. Call "getDrawingState" with your drawing ID');
    console.log('4. Look for "ballMax" field in the result');
}

// Add help text option
if (process.argv.includes('--help') || process.argv.includes('-h')) {
    console.log('🎫 Ticket Unpacker Help');
    console.log('=======================');
    console.log('');
    console.log('This script decodes packed ticket numbers from the Jackpot jackpot contract.');
    console.log('');
    console.log('Usage:');
    console.log('  node unpack-ticket.js <packedTicket> <maxNormalBall>');
    console.log('');
    console.log('Parameters:');
    console.log('  packedTicket    The packed ticket number from getTicketInfo() call');
    console.log('  maxNormalBall   The maximum normal ball number for the drawing');
    console.log('');
    console.log('Examples:');
    console.log('  node unpack-ticket.js 123456789 30');
    console.log('  node unpack-ticket.js "0x1e240" 30');
    console.log('');
    printEtherscanHelp();
    process.exit(0);
}

// Run the script
main();