export declare const StateDiscriminator: Readonly<{
    readonly treeAccount: 1;
    readonly protocolConfig: 3;
    readonly zoneConfig: 4;
    readonly splAssetRegistry: 5;
    readonly splAssetCounter: 6;
}>;
export declare const FIRST_ASSET_ID = 2n;
export declare const STATE_HEIGHT = 32;
export declare const ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE = 30000n;
export declare const ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE = 250n;
export declare const ADDRESS_TREE_HEIGHT = 40;
export declare const ADDRESS_TREE_ROOT_HISTORY_CAPACITY = 120;
export declare const FORESTER_REIMBURSEMENT_LAMPORTS = 5000n;
export declare function foresterFeePerQueueElement(zkpBatchSize: bigint): bigint | undefined;
export declare const TREE_ACCOUNT_SIZE = 1185664;
export declare const STATE_ROOT_OFFSET = 16;
