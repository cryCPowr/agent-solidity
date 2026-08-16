import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";
import { environments, environmentToIgnitionParams } from "../deploy/config/environments";

async function generateParameterFiles() {
  // Create ignition/parameters directory if it doesn't exist
  const paramsDir = join(__dirname, "../ignition/parameters");
  try {
    mkdirSync(paramsDir, { recursive: true });
  } catch (error) {
    // Directory might already exist, that's fine
  }

  // Generate parameter files for each environment
  for (const [envName, config] of Object.entries(environments)) {
    console.log(`Generating parameter file for ${envName}...`);
    
    // Convert environment config to Ignition parameters format
    const ignitionParams = environmentToIgnitionParams(config);
    
    // Wrap in the required module structure for Hardhat Ignition
    const parameterFile = {
      JackpotSystem: ignitionParams
    };
    
    // Write to file
    const filePath = join(paramsDir, `${envName}.json`);
    writeFileSync(filePath, JSON.stringify(parameterFile, null, 2));
    
    console.log(`✅ Generated ${filePath}`);
  }

  console.log("\n🎉 All parameter files generated successfully!");
  console.log("\nNext steps:");
  console.log("1. Update the multisig addresses in the generated parameter files");
  console.log("2. Verify external contract addresses (entropy, USDC) are correct");
  console.log("3. Set up your .env file with RPC URLs and private keys");
  console.log("4. Run deployment with: npm run deploy:testnet or npm run deploy:production");
}

// Run the script if called directly
if (require.main === module) {
  generateParameterFiles().catch(console.error);
}

export { generateParameterFiles };