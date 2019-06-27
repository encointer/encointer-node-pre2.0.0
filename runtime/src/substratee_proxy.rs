/*
	Copyright 2019 Supercomputing Systems AG

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

*/

use rstd::prelude::*;

use support::{decl_storage, decl_module,
	dispatch::Result, decl_event};
use system::ensure_signed;

 pub trait Trait: balances::Trait {
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

 decl_event!(
	pub enum Event<T>
	where
		<T as system::Trait>::AccountId,
	{
		Forwarded(AccountId, Vec<u8>),
		CallConfirmed(AccountId, Vec<u8>),
	}
);

 decl_storage! {
	trait Store for Module<T: Trait> as substraTEEProxyStorage {
	}
}

 decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {

 		fn deposit_event<T>() = default;

		// the substraTEE-client calls this function to pass the payload into the TEE
 		pub fn call_worker(origin, payload: Vec<u8>) -> Result {
			let sender = ensure_signed(origin)?;

 			Self::deposit_event(RawEvent::Forwarded(sender, payload));

 			Ok(())
		}

		// the substraTEE-worker calls this function for every processed call to confirm a state update
 		pub fn confirm_call(origin, payload: Vec<u8>) -> Result {
			let sender = ensure_signed(origin)?;
			//FIXME: only enclave is allowed to call this. But we'll need an enclave registry first. right now, people have to manually check AccountID
 			Self::deposit_event(RawEvent::CallConfirmed(sender, payload));

 			Ok(())
		}


	}
}