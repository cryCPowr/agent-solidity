const { run } = require("hardhat");

async function main() {
  const deployedAddresses = {
    "JackpotSystem#Jackpot": "0xDF61A9c7d6B35AA2C9eB4F919d46068E24bFAa3C",
    "JackpotSystem#FisherYatesRejection": "0xF849b7C12a4aa45e793B5caf4A93748B0101B8b3",
    "JackpotSystem#USDCMock": "0xD1Af44EfaD81A74E1D113b354701D4D81A3847ad",
    "JackpotSystem#GuaranteedMinimumPayoutCalculator": "0xF5bD557a0079843f01ED3C34EaE26A23E72325B8",
    "JackpotSystem#JackpotLPManager": "0xdb22926FF651C2982D7570A6731c304aB8fcc7b5",
    "JackpotSystem#JackpotTicketNFT": "0x20BbdC267E3Bd7DfD852569AcE4053595c80DEfb",
    "JackpotSystem#ScaledEntropyProvider": "0x79abA78e34F6B2ce138dBF88ef20C1571f47B1fC",
    "JackpotSystem#JackpotBridgeManager": "0x7ca79e75E0Bb762D6576A790a5dff09C95B37C09"
  };

  console.log("🔍 Starting contract verification on Base Sepolia...\n");

  try {
    // 1. Verify FisherYatesRejection (Library - no constructor args)
    console.log("1. Verifying FisherYatesRejection library...");
    await run("verify:verify", {
      address: deployedAddresses["JackpotSystem#FisherYatesRejection"],
      constructorArguments: []
    });
    console.log("✅ FisherYatesRejection verified!\n");

    // 2. Verify USDCMock 
    console.log("2. Verifying USDCMock...");
    await run("verify:verify", {
      address: deployedAddresses["JackpotSystem#USDCMock"],
      constructorArguments: [
        "1000000000000000", // usdcInitialSupply
        "USD Coin (Test)",  // usdcName
        "USDC"              // usdcSymbol
      ]
    });
    console.log("✅ USDCMock verified!\n");

    // 3. Verify Jackpot (Main contract)
    console.log("3. Verifying Jackpot...");
    await run("verify:verify", {
      address: deployedAddresses["JackpotSystem#Jackpot"],
      constructorArguments: [
        "86400",                    // drawingDurationInSeconds
        "30",                       // normalBallMax
        "5",                        // bonusballMin
        "300000000000000000",       // lpEdgeTarget
        "200000000000000000",       // reserveRatio
        "65000000000000000",        // referralFee
        "50000000000000000",        // referralWinShare
        "10000000000000000",        // protocolFee
        "1000000",                  // protocolFeeThreshold
        "1000000",                  // ticketPrice
        "5",                        // maxReferrers
        "1000000"                   // entropyGasLimit
      ]
    });
    console.log("✅ Jackpot verified!\n");

    // 4. Verify JackpotLPManager
    console.log("4. Verifying JackpotLPManager...");
    await run("verify:verify", {
      address: deployedAddresses["JackpotSystem#JackpotLPManager"],
      constructorArguments: [
        deployedAddresses["JackpotSystem#Jackpot"] // jackpot address
      ]
    });
    console.log("✅ JackpotLPManager verified!\n");

    // 5. Verify JackpotTicketNFT
    console.log("5. Verifying JackpotTicketNFT...");
    await run("verify:verify", {
      address: deployedAddresses["JackpotSystem#JackpotTicketNFT"],
      constructorArguments: [
        deployedAddresses["JackpotSystem#Jackpot"] // jackpot address
      ]
    });
    console.log("✅ JackpotTicketNFT verified!\n");

    // 6. Verify GuaranteedMinimumPayoutCalculator
    console.log("6. Verifying GuaranteedMinimumPayoutCalculator...");
    await run("verify:verify", {
      address: deployedAddresses["JackpotSystem#GuaranteedMinimumPayoutCalculator"],
      constructorArguments: [
        deployedAddresses["JackpotSystem#Jackpot"], // jackpot address
        "1000000", // minimumPayout
        [false,true,false,true,true,true,true,true,true,true,true,true], // minPayoutTiers
        ["0","170000000000000000","0","130000000000000000","120000000000000000","50000000000000000","50000000000000000","20000000000000000","20000000000000000","10000000000000000","40000000000000000","390000000000000000"] // premiumTierWeights
      ]
    });
    console.log("✅ GuaranteedMinimumPayoutCalculator verified!\n");

    // 7. Verify ScaledEntropyProvider (with library)
    console.log("7. Verifying ScaledEntropyProvider...");
    await run("verify:verify", {
      address: deployedAddresses["JackpotSystem#ScaledEntropyProvider"],
      constructorArguments: [
        "0x41c9e39574F40Ad34c79f1C99B66A45eFB830d4c", // entropyAddress
        "0x6CC14824Ea2918f5De5C2f75A9Da968ad4BD6344"  // entropyProviderAddress
      ],
      libraries: {
        FisherYatesRejection: deployedAddresses["JackpotSystem#FisherYatesRejection"]
      }
    });
    console.log("✅ ScaledEntropyProvider verified!\n");

    // 8. Verify JackpotBridgeManager
    console.log("8. Verifying JackpotBridgeManager...");
    await run("verify:verify", {
      address: deployedAddresses["JackpotSystem#JackpotBridgeManager"],
      constructorArguments: [
        deployedAddresses["JackpotSystem#Jackpot"],     // jackpot
        deployedAddresses["JackpotSystem#JackpotTicketNFT"], // jackpotNFT  
        deployedAddresses["JackpotSystem#USDCMock"],    // usdc
        "MegapotBridge",  // bridgeName
        "1.0.0"           // bridgeVersion
      ]
    });
    console.log("✅ JackpotBridgeManager verified!\n");

    console.log("🎉 All contracts verified successfully!");

  } catch (error) {
    console.error("❌ Verification failed:", error.message);
    
    if (error.message.includes("Already Verified")) {
      console.log("✅ Contract is already verified on Etherscan");
    } else if (error.message.includes("Etherscan API")) {
      console.log("⚠️  Etherscan API issue - contracts may still verify later");
      console.log("💡 Check manually at: https://sepolia.basescan.org/");
    }
  }
}

main().catch(console.error);