#![cfg(test)]

use super::*;

use frame_support::{ord_parameter_types, parameter_types, weights::Weight};
use frame_system::{self as system};
use sp_core::hashing::blake2_128;
use sp_core::H256;
use sp_runtime::{
	testing::Header,
	traits::{AccountIdConversion, BlakeTwo256, Block as BlockT, IdentityLookup},
	ModuleId, Perbill,
};

use crate::{self as example, Config};
pub use pallet_balances as balances;

parameter_types! {
	pub const BlockHashCount: u64 = 250;
	pub const MaximumBlockWeight: Weight = 1024;
	pub const MaximumBlockLength: u32 = 2 * 1024;
	pub const AvailableBlockRatio: Perbill = Perbill::one();
	pub const MaxLocks: u32 = 100;
}

impl frame_system::Config for Test {
	type BaseCallFilter = ();
	type BlockWeights = ();
	type BlockLength = ();
	type DbWeight = ();
	type Origin = Origin;
	type Index = u64;
	type Call = Call;
	type BlockNumber = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = u64;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Header = Header;
	type Event = Event;
	type BlockHashCount = BlockHashCount;
	type Version = ();
	type PalletInfo = ();
	type AccountData = pallet_balances::AccountData<u64>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = ();
}

parameter_types! {
	pub const ExistentialDeposit: u64 = 1;
}

ord_parameter_types! {
	pub const One: u64 = 1;
}

impl pallet_balances::Config for Test {
	type Balance = u64;
	type DustRemoval = ();
	type Event = Event;
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
	type MaxLocks = MaxLocks;
	type WeightInfo = ();
}

parameter_types! {
	pub const TestChainId: u8 = 5;
	pub const ProposalLifetime: u64 = 100;
}

impl chainbridge::Config for Test {
	type Event = Event;
	type AdminOrigin = frame_system::EnsureRoot<Self::AccountId>;
	type Proposal = Call;
	type ChainId = TestChainId;
	type ProposalLifetime = ProposalLifetime;
}

parameter_types! {
	pub NativeTokenId: chainbridge::ResourceId = chainbridge::derive_resource_id(1, &blake2_128(b"EDG"));
}

parameter_types! {
	pub const NativeTransferFee: u64 = 1;
}

impl Config for Test {
	type Event = Event;
	type BridgeOrigin = chainbridge::EnsureBridge<Test>;
	type Currency = Balances;
	type NativeTokenId = NativeTokenId;
	type NativeTransferFee = NativeTransferFee;
}

pub type Block = sp_runtime::generic::Block<Header, UncheckedExtrinsic>;
pub type UncheckedExtrinsic = sp_runtime::generic::UncheckedExtrinsic<u32, u64, Call, ()>;

frame_support::construct_runtime!(
	pub enum Test where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = UncheckedExtrinsic
	{
		System: frame_system::{Module, Call, Config, Storage, Event<T>},
		Balances: balances::{Module, Call, Storage, Config<T>, Event<T>},
		Bridge: chainbridge::{Module, Call, Storage, Event<T>},
        Example: example::{Module, Call, Event<T>}
	}
);

pub const RELAYER_A: u64 = 0x2;
pub const RELAYER_B: u64 = 0x3;
pub const RELAYER_C: u64 = 0x4;
pub const ENDOWED_BALANCE: u64 = 100_000_000;

pub fn new_test_ext() -> sp_io::TestExternalities {
	let bridge_id = ModuleId(*b"cb/bridg").into_account();
	let mut t = frame_system::GenesisConfig::default()
		.build_storage::<Test>()
		.unwrap();
	balances::GenesisConfig::<Test> {
		balances: vec![(bridge_id, ENDOWED_BALANCE), (RELAYER_A, ENDOWED_BALANCE)],
	}
	.assimilate_storage(&mut t)
	.unwrap();
	let mut ext = sp_io::TestExternalities::new(t);
	ext.execute_with(|| System::set_block_number(1));
	ext
}

fn last_event() -> Event {
	system::Module::<Test>::events()
		.pop()
		.map(|e| e.event)
		.expect("Event expected")
}

pub fn expect_event<E: Into<Event>>(e: E) {
	assert_eq!(last_event(), e.into());
}

// Checks events against the latest. A contiguous set of events must be provided. They must
// include the most recent event, but do not have to include every past event.
pub fn assert_events(mut expected: Vec<Event>) {
	let mut actual: Vec<Event> = system::Module::<Test>::events()
		.iter()
		.map(|e| e.event.clone())
		.collect();

	expected.reverse();

	for evt in expected {
		let next = actual.pop().expect("event expected");
		assert_eq!(next, evt.into(), "Events don't match");
	}
}
