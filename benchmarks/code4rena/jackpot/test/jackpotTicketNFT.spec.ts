import { ethers } from "hardhat";
import DeployHelper from "@utils/deploys";

import {
  getWaffleExpect,
  getAccounts
} from "@utils/test/index";
import { Account } from "@utils/test";
import { ExtendedTrackedTicket, TrackedTicket } from "@utils/types";

import { JackpotTicketNFT, MockJackpot } from "@utils/contracts";
import { takeSnapshot, SnapshotRestorer } from "@nomicfoundation/hardhat-toolbox/network-helpers";

const expect = getWaffleExpect();

describe("JackpotTicketNFT", () => {
  let owner: Account;
  let user1: Account;
  let user2: Account;
  let unauthorized: Account;

  let jackpotTicketNFT: JackpotTicketNFT;
  let mockJackpot: MockJackpot;
  let snapshot: SnapshotRestorer;

  const DRAWING_ID_1 = 1n;
  const DRAWING_ID_2 = 2n;
  const TICKET_ID_1 = 1001n;
  const TICKET_ID_2 = 1002n;
  const TICKET_ID_3 = 1003n;
  const PACKED_TICKET_1 = 0x123456n;
  const PACKED_TICKET_2 = 0x789ABCn;
  const PACKED_TICKET_3 = 0xDEF012n;
  const REFERRAL_SCHEME = ethers.keccak256(ethers.toUtf8Bytes("referral"));

  beforeEach(async () => {
    [owner, user1, user2, unauthorized] = await getAccounts();
    
    const deployer = new DeployHelper(owner.wallet);
    mockJackpot = await deployer.deployMockJackpot();
    jackpotTicketNFT = await deployer.deployJackpotTicketNFT(await mockJackpot.getAddress());
    
    snapshot = await takeSnapshot();
  });

  beforeEach(async () => {
    await snapshot.restore();
  });

  describe("#constructor", () => {
    it("should set the jackpot address correctly", async () => {
      expect(await jackpotTicketNFT.jackpot()).to.equal(await mockJackpot.getAddress());
    });

    it("should have correct name and symbol", async () => {
      expect(await jackpotTicketNFT.name()).to.equal("Jackpot");
      expect(await jackpotTicketNFT.symbol()).to.equal("JACKPOT");
    });
  });

  describe("#mintTicket", () => {
    let subjectRecipient: string;
    let subjectTicketId: bigint;
    let subjectDrawingId: bigint;
    let subjectPackedTicket: bigint;
    let subjectReferralScheme: string;
    let subjectCaller: Account;

    beforeEach(async () => {
      subjectRecipient = user1.address;
      subjectTicketId = TICKET_ID_1;
      subjectDrawingId = DRAWING_ID_1;
      subjectPackedTicket = PACKED_TICKET_1;
      subjectReferralScheme = REFERRAL_SCHEME;
      subjectCaller = owner; // Will be overridden in specific test cases
    });

    async function subject(): Promise<any> {
      if (subjectCaller === owner) {
        return await mockJackpot.mintTicket(
          await jackpotTicketNFT.getAddress(),
          subjectRecipient,
          subjectTicketId,
          subjectDrawingId,
          subjectPackedTicket,
          subjectReferralScheme
        );
      } else {
        return await jackpotTicketNFT.connect(subjectCaller.wallet).mintTicket(
          subjectRecipient,
          subjectTicketId,
          subjectDrawingId,
          subjectPackedTicket,
          subjectReferralScheme
        );
      }
    }

    describe("when called by jackpot contract", () => {
      it("should mint ticket to recipient", async () => {
        await subject();
        expect(await jackpotTicketNFT.ownerOf(subjectTicketId)).to.equal(subjectRecipient);
      });

      it("should store correct ticket information", async () => {
        await subject();
        const ticketInfo: TrackedTicket = await jackpotTicketNFT.getTicketInfo(subjectTicketId);
        expect(ticketInfo.drawingId).to.equal(subjectDrawingId);
        expect(ticketInfo.packedTicket).to.equal(subjectPackedTicket);
        expect(ticketInfo.referralScheme).to.equal(subjectReferralScheme);
      });

      it("should update user ticket tracking", async () => {
        await subject();
        const userTickets: ExtendedTrackedTicket[] = await jackpotTicketNFT.getUserTickets(subjectRecipient, subjectDrawingId);
        expect(userTickets.length).to.equal(1);
        expect(userTickets[0].ticket.drawingId).to.equal(subjectDrawingId);
        expect(userTickets[0].ticket.packedTicket).to.equal(subjectPackedTicket);
      });
    });

    describe("when called by unauthorized address", () => {
      beforeEach(async () => {
        subjectCaller = unauthorized;
      });

      it("should revert with UnauthorizedCaller", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotTicketNFT, "UnauthorizedCaller");
      });
    });
  });

  describe("#burnTicket", () => {
    let subjectTicketId: bigint;
    let subjectCaller: Account;

    beforeEach(async () => {
      subjectTicketId = TICKET_ID_1;
      subjectCaller = owner; // Will be overridden in specific test cases

      // Mint a ticket first
      await mockJackpot.mintTicket(
        await jackpotTicketNFT.getAddress(),
        user1.address,
        TICKET_ID_1,
        DRAWING_ID_1,
        PACKED_TICKET_1,
        REFERRAL_SCHEME
      );
    });

    async function subject(): Promise<any> {
      if (subjectCaller === owner) {
        return await mockJackpot.burnTicket(await jackpotTicketNFT.getAddress(), subjectTicketId);
      } else {
        return await jackpotTicketNFT.connect(subjectCaller.wallet).burnTicket(subjectTicketId);
      }
    }

    describe("when called by jackpot contract", () => {
      it("should burn the ticket", async () => {
        await subject();
        await expect(jackpotTicketNFT.ownerOf(subjectTicketId)).to.be.reverted;
      });

      it("should update user ticket tracking", async () => {
        let userTickets: ExtendedTrackedTicket[] = await jackpotTicketNFT.getUserTickets(user1.address, DRAWING_ID_1);
        expect(userTickets.length).to.equal(1);

        await subject();

        userTickets = await jackpotTicketNFT.getUserTickets(user1.address, DRAWING_ID_1);
        expect(userTickets.length).to.equal(0);
      });
    });

    describe("when called by unauthorized address", () => {
      beforeEach(async () => {
        subjectCaller = unauthorized;
      });

      it("should revert with UnauthorizedCaller", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotTicketNFT, "UnauthorizedCaller");
      });
    });
  });

  describe("#getTicketInfo", () => {
    let subjectTicketId: bigint;

    beforeEach(async () => {
      subjectTicketId = TICKET_ID_1;
    });

    async function subject(): Promise<any> {
      return await jackpotTicketNFT.getTicketInfo(subjectTicketId);
    }

    describe("when ticket exists", () => {
      beforeEach(async () => {
        await mockJackpot.mintTicket(
          await jackpotTicketNFT.getAddress(),
          user1.address,
          TICKET_ID_1,
          DRAWING_ID_1,
          PACKED_TICKET_1,
          REFERRAL_SCHEME
        );
      });

      it("should return correct ticket information", async () => {
        const ticketInfo: TrackedTicket = await subject();
        expect(ticketInfo.drawingId).to.equal(DRAWING_ID_1);
        expect(ticketInfo.packedTicket).to.equal(PACKED_TICKET_1);
        expect(ticketInfo.referralScheme).to.equal(REFERRAL_SCHEME);
      });
    });

    describe("when ticket does not exist", () => {
      beforeEach(async () => {
        subjectTicketId = 999n;
      });

      it("should return empty struct", async () => {
        const ticketInfo: TrackedTicket = await subject();
        expect(ticketInfo.drawingId).to.equal(0n);
        expect(ticketInfo.packedTicket).to.equal(0n);
        expect(ticketInfo.referralScheme).to.equal("0x0000000000000000000000000000000000000000000000000000000000000000");
      });
    });
  });

  describe("#getExtendedTicketInfo", () => {
    let subjectTicketId: bigint;

    beforeEach(async () => {
      subjectTicketId = TICKET_ID_1;
    });

    async function subject(): Promise<any> {
      return await jackpotTicketNFT.getExtendedTicketInfo(subjectTicketId);
    }

    describe("when ticket exists", () => {
      beforeEach(async () => {
        await mockJackpot.mintTicket(
          await jackpotTicketNFT.getAddress(),
          user1.address,
          TICKET_ID_1,
          DRAWING_ID_1,
          PACKED_TICKET_1,
          REFERRAL_SCHEME
        );
      });

      it("should return correct ticket information", async () => {
        const ticketInfo: ExtendedTrackedTicket = await subject();

        expect(ticketInfo.ticketId).to.equal(TICKET_ID_1);
        expect(ticketInfo.ticket.drawingId).to.equal(DRAWING_ID_1);
        expect(ticketInfo.ticket.packedTicket).to.equal(PACKED_TICKET_1);
        expect(ticketInfo.ticket.referralScheme).to.equal(REFERRAL_SCHEME);
        expect(ticketInfo.normals).to.deep.equal([1,2,3,4,5]);
        expect(ticketInfo.bonusball).to.equal(6);
      });
    });

    describe("when ticket does not exist", () => {
      beforeEach(async () => {
        subjectTicketId = BigInt(999);
      });

      it("should return empty struct", async () => {
        const ticketInfo: ExtendedTrackedTicket = await subject();

        expect(ticketInfo.ticketId).to.equal(999n);
        expect(ticketInfo.ticket.drawingId).to.equal(0n);
        expect(ticketInfo.ticket.packedTicket).to.equal(0n);
        expect(ticketInfo.ticket.referralScheme).to.equal("0x0000000000000000000000000000000000000000000000000000000000000000");
        expect(ticketInfo.normals).to.deep.equal([]);
        expect(ticketInfo.bonusball).to.equal(0);
      });
    });
  });

  describe("#getUserTickets", () => {
    let subjectUserAddress: string;
    let subjectDrawingId: bigint;

    beforeEach(async () => {
      subjectUserAddress = user1.address;
      subjectDrawingId = DRAWING_ID_1;
    });

    async function subject(): Promise<any> {
      return await jackpotTicketNFT.getUserTickets(subjectUserAddress, subjectDrawingId);
    }

    describe("when user has no tickets", () => {
      it("should return empty array", async () => {
        const userTickets: ExtendedTrackedTicket[] = await subject();
        expect(userTickets.length).to.equal(0);
      });
    });

    describe("when user has multiple tickets in same drawing", () => {
      beforeEach(async () => {
        await mockJackpot.mintTicket(
          await jackpotTicketNFT.getAddress(),
          user1.address,
          TICKET_ID_1,
          DRAWING_ID_1,
          PACKED_TICKET_1,
          REFERRAL_SCHEME
        );
        await mockJackpot.mintTicket(
          await jackpotTicketNFT.getAddress(),
          user1.address,
          TICKET_ID_2,
          DRAWING_ID_1,
          PACKED_TICKET_2,
          REFERRAL_SCHEME
        );
      });

      it("should return all tickets for specific drawing", async () => {
        const userTickets: ExtendedTrackedTicket[] = await subject();
        expect(userTickets.length).to.equal(2);
        expect(userTickets[0].ticketId).to.equal(TICKET_ID_1);
        expect(userTickets[1].ticketId).to.equal(TICKET_ID_2);
        expect(userTickets[0].ticket.packedTicket).to.equal(PACKED_TICKET_1);
        expect(userTickets[1].ticket.packedTicket).to.equal(PACKED_TICKET_2);
        expect(userTickets[0].normals).to.deep.equal([1,2,3,4,5]);
        expect(userTickets[1].normals).to.deep.equal([1,2,3,4,5]);
        expect(userTickets[0].bonusball).to.equal(6);
        expect(userTickets[1].bonusball).to.equal(6);
      });
    });

    describe("when user has tickets in multiple drawings", () => {
      beforeEach(async () => {
        await mockJackpot.mintTicket(
          await jackpotTicketNFT.getAddress(),
          user1.address,
          TICKET_ID_1,
          DRAWING_ID_1,
          PACKED_TICKET_1,
          REFERRAL_SCHEME
        );
        await mockJackpot.mintTicket(
          await jackpotTicketNFT.getAddress(),
          user1.address,
          TICKET_ID_2,
          DRAWING_ID_2,
          PACKED_TICKET_2,
          REFERRAL_SCHEME
        );
      });

      it("should return only tickets for specified drawing", async () => {
        const drawing1Tickets: ExtendedTrackedTicket[] = await subject();
        
        subjectDrawingId = DRAWING_ID_2;
        const drawing2Tickets: ExtendedTrackedTicket[] = await subject();

        expect(drawing1Tickets.length).to.equal(1);
        expect(drawing1Tickets[0].ticketId).to.equal(TICKET_ID_1);
        expect(drawing2Tickets.length).to.equal(1);
        expect(drawing1Tickets[0].ticket.packedTicket).to.equal(PACKED_TICKET_1);
        expect(drawing2Tickets[0].ticket.packedTicket).to.equal(PACKED_TICKET_2);
      });
    });
  });

  describe("#tokenURI", () => {
    let subjectTokenId: bigint;

    beforeEach(async () => {
      subjectTokenId = TICKET_ID_1;
    });

    async function subject(): Promise<any> {
      return await jackpotTicketNFT.tokenURI(subjectTokenId);
    }

    it("should return empty string for any token", async () => {
      const result = await subject();
      expect(result).to.equal("");
    });
  });

  describe("Token transfers", () => {
    let subjectFrom: string;
    let subjectTo: string;
    let subjectTokenId: bigint;

    beforeEach(async () => {
      subjectFrom = user1.address;
      subjectTo = user2.address;
      subjectTokenId = TICKET_ID_2;

      // Mint three tickets to user1
      await mockJackpot.mintTicket(
        await jackpotTicketNFT.getAddress(),
        user1.address,
        TICKET_ID_1,
        DRAWING_ID_1,
        PACKED_TICKET_1,
        REFERRAL_SCHEME
      );
      await mockJackpot.mintTicket(
        await jackpotTicketNFT.getAddress(),
        user1.address,
        TICKET_ID_2,
        DRAWING_ID_1,
        PACKED_TICKET_2,
        REFERRAL_SCHEME
      );
      await mockJackpot.mintTicket(
        await jackpotTicketNFT.getAddress(),
        user1.address,
        TICKET_ID_3,
        DRAWING_ID_1,
        PACKED_TICKET_3,
        REFERRAL_SCHEME
      );
    });

    async function subject(): Promise<any> {
      return await jackpotTicketNFT.connect(user1.wallet).transferFrom(subjectFrom, subjectTo, subjectTokenId);
    }

    it("should update user ticket tracking", async () => {
      let user1Tickets: ExtendedTrackedTicket[] = await jackpotTicketNFT.getUserTickets(user1.address, DRAWING_ID_1);
      let user2Tickets: ExtendedTrackedTicket[] = await jackpotTicketNFT.getUserTickets(user2.address, DRAWING_ID_1);
      expect(user1Tickets.length).to.equal(3);
      expect(user2Tickets.length).to.equal(0);

      await subject();

      user1Tickets = await jackpotTicketNFT.getUserTickets(user1.address, DRAWING_ID_1);
      user2Tickets = await jackpotTicketNFT.getUserTickets(user2.address, DRAWING_ID_1);
      expect(user1Tickets.length).to.equal(2);
      expect(user2Tickets.length).to.equal(1);
      expect(user2Tickets[0].ticket.packedTicket).to.equal(PACKED_TICKET_2);
    });

    describe("when transferring middle ticket", () => {
      beforeEach(async () => {
        subjectTokenId = TICKET_ID_2;
      });

      it("should handle swap and pop correctly", async () => {
        const user1TicketsBefore: ExtendedTrackedTicket[] = await jackpotTicketNFT.getUserTickets(user1.address, DRAWING_ID_1);
        expect(user1TicketsBefore.length).to.equal(3);
        
        const ticketPackeds = user1TicketsBefore.map(t => t.ticket.packedTicket);
        expect(ticketPackeds).to.include(PACKED_TICKET_1);
        expect(ticketPackeds).to.include(PACKED_TICKET_2);
        expect(ticketPackeds).to.include(PACKED_TICKET_3);

        await subject();

        const user1TicketsAfter: ExtendedTrackedTicket[] = await jackpotTicketNFT.getUserTickets(user1.address, DRAWING_ID_1);
        const user2TicketsAfter: ExtendedTrackedTicket[] = await jackpotTicketNFT.getUserTickets(user2.address, DRAWING_ID_1);
        
        expect(user1TicketsAfter.length).to.equal(2);
        expect(user2TicketsAfter.length).to.equal(1);
        expect(user2TicketsAfter[0].ticket.packedTicket).to.equal(PACKED_TICKET_2);
        
        const remainingPackeds = user1TicketsAfter.map(t => t.ticket.packedTicket);
        expect(remainingPackeds).to.include(PACKED_TICKET_1);
        expect(remainingPackeds).to.include(PACKED_TICKET_3);
      });
    });

    describe("when performing multiple transfers", () => {
      beforeEach(async () => {
        await jackpotTicketNFT.connect(user1.wallet).transferFrom(user1.address, user2.address, TICKET_ID_1);
        await jackpotTicketNFT.connect(user1.wallet).transferFrom(user1.address, user2.address, TICKET_ID_3);
      });

      it("should handle multiple transfers correctly", async () => {
        const user1Tickets: ExtendedTrackedTicket[] = await jackpotTicketNFT.getUserTickets(user1.address, DRAWING_ID_1);
        const user2Tickets: ExtendedTrackedTicket[] = await jackpotTicketNFT.getUserTickets(user2.address, DRAWING_ID_1);

        expect(user1Tickets.length).to.equal(1);
        expect(user2Tickets.length).to.equal(2);
        expect(user1Tickets[0].ticket.packedTicket).to.equal(PACKED_TICKET_2);

        const user2Packeds = user2Tickets.map(t => t.ticket.packedTicket);
        expect(user2Packeds).to.include(PACKED_TICKET_1);
        expect(user2Packeds).to.include(PACKED_TICKET_3);
      });
    });
  });
});