use super::tx_config::TxConfig;
use celestia_client::types::blob::RawBlob;
use celestia_client::types::state::{
    AccAddress, Address, Balance, QueryDelegationResponse, QueryRedelegationsResponse,
    QueryUnbondingDelegationResponse, RawTxResponse, Uint, ValAddress,
};
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

#[rpc(server, client)]
pub trait State {
    /// AccountAddress retrieves the address of the node's account/signer
    #[method(name = "state.AccountAddress")]
    async fn state_account_address(&self) -> Result<Address, ErrorObjectOwned>;

    /// Balance retrieves the Celestia coin balance for the node's account/signer and verifies it against the corresponding block's AppHash.
    #[method(name = "state.Balance")]
    async fn state_balance(&self) -> Result<Balance, ErrorObjectOwned>;

    /// BalanceForAddress retrieves the Celestia coin balance for the given address and verifies the returned balance against the corresponding block's AppHash.
    ///
    /// # NOTE
    ///
    /// The balance returned is the balance reported by the block right before the node's current head (head-1). This is due to the fact that for block N, the block's `AppHash` is the result of applying the previous block's transaction list.
    #[method(name = "state.BalanceForAddress")]
    async fn state_balance_for_address(&self, addr: Address) -> Result<Balance, ErrorObjectOwned>;

    /// BeginRedelegate sends a user's delegated tokens to a new validator for redelegation.
    #[method(name = "state.BeginRedelegate")]
    async fn state_begin_redelegate(
        &self,
        src: ValAddress,
        dest: ValAddress,
        amount: Uint,
        config: TxConfig,
    ) -> Result<RawTxResponse, ErrorObjectOwned>;

    /// CancelUnbondingDelegation cancels a user's pending undelegation from a validator.
    #[method(name = "state.CancelUnbondingDelegation")]
    async fn state_cancel_unbonding_delegation(
        &self,
        addr: ValAddress,
        amount: Uint,
        height: Uint,
        config: TxConfig,
    ) -> Result<RawTxResponse, ErrorObjectOwned>;

    /// Delegate sends a user's liquid tokens to a validator for delegation.
    #[method(name = "state.Delegate")]
    async fn state_delegate(
        &self,
        addr: ValAddress,
        amount: Uint,
        config: TxConfig,
    ) -> Result<RawTxResponse, ErrorObjectOwned>;

    /// IsStopped checks if the Module's context has been stopped.
    #[method(name = "state.IsStopped")]
    async fn state_is_stopped(&self) -> Result<bool, ErrorObjectOwned>;

    /// QueryDelegation retrieves the delegation information between a delegator and a validator.
    #[method(name = "state.QueryDelegation")]
    async fn state_query_delegation(
        &self,
        addr: ValAddress,
    ) -> Result<QueryDelegationResponse, ErrorObjectOwned>;

    /// QueryRedelegations retrieves the status of the redelegations between a delegator and a validator.
    #[method(name = "state.QueryRedelegations")]
    async fn state_query_redelegations(
        &self,
        src: ValAddress,
        dest: ValAddress,
    ) -> Result<QueryRedelegationsResponse, ErrorObjectOwned>;

    /// QueryUnbonding retrieves the unbonding status between a delegator and a validator.
    #[method(name = "state.QueryUnbonding")]
    async fn state_query_unbonding(
        &self,
        addr: ValAddress,
    ) -> Result<QueryUnbondingDelegationResponse, ErrorObjectOwned>;

    /// SubmitPayForBlob builds, signs and submits a PayForBlob transaction.
    #[method(name = "state.SubmitPayForBlob")]
    async fn state_submit_pay_for_blob(
        &self,
        blobs: Vec<RawBlob>,
        config: TxConfig,
    ) -> Result<RawTxResponse, ErrorObjectOwned>;

    /// Transfer sends the given amount of coins from default wallet of the node to the given account address.
    #[method(name = "state.Transfer")]
    async fn state_transfer(
        &self,
        to: AccAddress,
        amount: Uint,
        config: TxConfig,
    ) -> Result<RawTxResponse, ErrorObjectOwned>;

    /// Undelegate undelegates a user's delegated tokens, unbonding them from the current validator.
    #[method(name = "Undelegate")]
    async fn state_undelegate(
        &self,
        addr: ValAddress,
        amount: Uint,
        config: TxConfig,
    ) -> Result<RawTxResponse, ErrorObjectOwned>;
}

pub struct StateServerImpl;

#[async_trait]
impl StateServer for StateServerImpl {
    async fn state_submit_pay_for_blob(
        &self,
        blobs: Vec<RawBlob>,
        config: TxConfig,
    ) -> Result<RawTxResponse, ErrorObjectOwned> {
        todo!()
    }

    async fn state_account_address(&self) -> Result<Address, ErrorObjectOwned> {
        unimplemented!()
    }

    async fn state_balance(&self) -> Result<Balance, ErrorObjectOwned> {
        unimplemented!()
    }

    #[allow(unused_variables)]
    async fn state_balance_for_address(&self, addr: Address) -> Result<Balance, ErrorObjectOwned> {
        unimplemented!()
    }

    #[allow(unused_variables)]
    async fn state_begin_redelegate(
        &self,
        src: ValAddress,
        dest: ValAddress,
        amount: Uint,
        config: TxConfig,
    ) -> Result<RawTxResponse, ErrorObjectOwned> {
        unimplemented!()
    }

    #[allow(unused_variables)]
    async fn state_cancel_unbonding_delegation(
        &self,
        addr: ValAddress,
        amount: Uint,
        height: Uint,
        config: TxConfig,
    ) -> Result<RawTxResponse, ErrorObjectOwned> {
        unimplemented!()
    }

    #[allow(unused_variables)]
    async fn state_delegate(
        &self,
        addr: ValAddress,
        amount: Uint,
        config: TxConfig,
    ) -> Result<RawTxResponse, ErrorObjectOwned> {
        unimplemented!()
    }

    #[allow(unused_variables)]
    async fn state_is_stopped(&self) -> Result<bool, ErrorObjectOwned> {
        unimplemented!()
    }

    #[allow(unused_variables)]
    async fn state_query_delegation(
        &self,
        addr: ValAddress,
    ) -> Result<QueryDelegationResponse, ErrorObjectOwned> {
        unimplemented!()
    }

    #[allow(unused_variables)]
    async fn state_query_redelegations(
        &self,
        src: ValAddress,
        dest: ValAddress,
    ) -> Result<QueryRedelegationsResponse, ErrorObjectOwned> {
        unimplemented!()
    }

    #[allow(unused_variables)]
    async fn state_query_unbonding(
        &self,
        addr: ValAddress,
    ) -> Result<QueryUnbondingDelegationResponse, ErrorObjectOwned> {
        unimplemented!()
    }

    #[allow(unused_variables)]
    async fn state_transfer(
        &self,
        to: AccAddress,
        amount: Uint,
        config: TxConfig,
    ) -> Result<RawTxResponse, ErrorObjectOwned> {
        unimplemented!()
    }

    #[allow(unused_variables)]
    async fn state_undelegate(
        &self,
        addr: ValAddress,
        amount: Uint,
        config: TxConfig,
    ) -> Result<RawTxResponse, ErrorObjectOwned> {
        unimplemented!()
    }
}
