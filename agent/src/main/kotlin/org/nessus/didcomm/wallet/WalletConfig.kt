package org.nessus.didcomm.wallet

import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.model.LedgerRole
import org.nessus.didcomm.model.StorageType

data class WalletConfig(
    val name: String,
    val agentType: AgentType?,
    val storageType: StorageType?,
    val walletKey: String?,
    val ledgerRole: LedgerRole?,
    val trusteeWallet: AcapyWallet?,
    val publicDidMethod: DidMethod?,
    val options: Map<String, Any>,
    val mayExist: Boolean,
)