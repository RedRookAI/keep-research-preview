const B3_CAS_OPERATION_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-b3-operation"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "operationKind",
        spec: RSpec::Identifier {
            values: Some(&["compare-and-advance"]),
        },
    },
    RFieldSpec {
        name: "scopeKey",
        spec: RSpec::Record(&[
            RFieldSpec {
                name: "authorityId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "namespace",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "scope",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "genesisRootDigest",
                spec: RSpec::Digest("GenesisRootEnvelopeDigest"),
            },
        ]),
    },
    RFieldSpec {
        name: "expectedStateDigest",
        spec: RSpec::Digest("B3StateDigest"),
    },
    RFieldSpec {
        name: "newStateDigest",
        spec: RSpec::Digest("B3StateDigest"),
    },
    RFieldSpec {
        name: "callerPurpose",
        spec: RSpec::Tagged {
            tag: "purpose",
            variants: &[
                VariantSpec {
                    name: "root-update",
                    spec: RSpec::Record(&[
                        RFieldSpec {
                            name: "purpose",
                            spec: RSpec::Identifier {
                                values: Some(&["root-update"]),
                            },
                        },
                        RFieldSpec {
                            name: "authorization",
                            spec: RSpec::Tagged {
                                tag: "kind",
                                variants: &[
                                    VariantSpec {
                                        name: "root-update",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["root-update"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest("RootEnvelopeDigest"),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "revocation",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["revocation"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest("RevocationEnvelopeDigest"),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "rollback",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["rollback"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest(
                                                    "RollbackAuthorizationEnvelopeDigest",
                                                ),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "recovery",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["recovery"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest(
                                                    "RevocationRecoveryEnvelopeDigest",
                                                ),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "deployment",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["deployment"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest("DeploymentEnvelopeDigest"),
                                            },
                                        ]),
                                    },
                                ],
                            },
                        },
                    ]),
                },
                VariantSpec {
                    name: "revocation-advance",
                    spec: RSpec::Record(&[
                        RFieldSpec {
                            name: "purpose",
                            spec: RSpec::Identifier {
                                values: Some(&["revocation-advance"]),
                            },
                        },
                        RFieldSpec {
                            name: "authorization",
                            spec: RSpec::Tagged {
                                tag: "kind",
                                variants: &[
                                    VariantSpec {
                                        name: "root-update",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["root-update"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest("RootEnvelopeDigest"),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "revocation",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["revocation"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest("RevocationEnvelopeDigest"),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "rollback",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["rollback"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest(
                                                    "RollbackAuthorizationEnvelopeDigest",
                                                ),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "recovery",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["recovery"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest(
                                                    "RevocationRecoveryEnvelopeDigest",
                                                ),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "deployment",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["deployment"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest("DeploymentEnvelopeDigest"),
                                            },
                                        ]),
                                    },
                                ],
                            },
                        },
                    ]),
                },
                VariantSpec {
                    name: "rollback",
                    spec: RSpec::Record(&[
                        RFieldSpec {
                            name: "purpose",
                            spec: RSpec::Identifier {
                                values: Some(&["rollback"]),
                            },
                        },
                        RFieldSpec {
                            name: "authorization",
                            spec: RSpec::Tagged {
                                tag: "kind",
                                variants: &[
                                    VariantSpec {
                                        name: "root-update",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["root-update"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest("RootEnvelopeDigest"),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "revocation",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["revocation"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest("RevocationEnvelopeDigest"),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "rollback",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["rollback"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest(
                                                    "RollbackAuthorizationEnvelopeDigest",
                                                ),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "recovery",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["recovery"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest(
                                                    "RevocationRecoveryEnvelopeDigest",
                                                ),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "deployment",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["deployment"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest("DeploymentEnvelopeDigest"),
                                            },
                                        ]),
                                    },
                                ],
                            },
                        },
                    ]),
                },
                VariantSpec {
                    name: "recovery",
                    spec: RSpec::Record(&[
                        RFieldSpec {
                            name: "purpose",
                            spec: RSpec::Identifier {
                                values: Some(&["recovery"]),
                            },
                        },
                        RFieldSpec {
                            name: "authorization",
                            spec: RSpec::Tagged {
                                tag: "kind",
                                variants: &[
                                    VariantSpec {
                                        name: "root-update",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["root-update"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest("RootEnvelopeDigest"),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "revocation",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["revocation"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest("RevocationEnvelopeDigest"),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "rollback",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["rollback"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest(
                                                    "RollbackAuthorizationEnvelopeDigest",
                                                ),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "recovery",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["recovery"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest(
                                                    "RevocationRecoveryEnvelopeDigest",
                                                ),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "deployment",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["deployment"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest("DeploymentEnvelopeDigest"),
                                            },
                                        ]),
                                    },
                                ],
                            },
                        },
                    ]),
                },
                VariantSpec {
                    name: "deployment-advance",
                    spec: RSpec::Record(&[
                        RFieldSpec {
                            name: "purpose",
                            spec: RSpec::Identifier {
                                values: Some(&["deployment-advance"]),
                            },
                        },
                        RFieldSpec {
                            name: "authorization",
                            spec: RSpec::Tagged {
                                tag: "kind",
                                variants: &[
                                    VariantSpec {
                                        name: "root-update",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["root-update"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest("RootEnvelopeDigest"),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "revocation",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["revocation"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest("RevocationEnvelopeDigest"),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "rollback",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["rollback"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest(
                                                    "RollbackAuthorizationEnvelopeDigest",
                                                ),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "recovery",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["recovery"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest(
                                                    "RevocationRecoveryEnvelopeDigest",
                                                ),
                                            },
                                        ]),
                                    },
                                    VariantSpec {
                                        name: "deployment",
                                        spec: RSpec::Record(&[
                                            RFieldSpec {
                                                name: "kind",
                                                spec: RSpec::Identifier {
                                                    values: Some(&["deployment"]),
                                                },
                                            },
                                            RFieldSpec {
                                                name: "authorizationEnvelopeDigest",
                                                spec: RSpec::Digest("DeploymentEnvelopeDigest"),
                                            },
                                        ]),
                                    },
                                ],
                            },
                        },
                    ]),
                },
            ],
        },
    },
    RFieldSpec {
        name: "requestNonce",
        spec: RSpec::Bytes {
            exact: Some(32usize),
            maximum: None,
        },
    },
]);
const B3_GENESIS_OPERATION_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-b3-operation"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "operationKind",
        spec: RSpec::Identifier {
            values: Some(&["genesis"]),
        },
    },
    RFieldSpec {
        name: "genesisBaseDigest",
        spec: RSpec::Digest("GenesisBaseDigest"),
    },
    RFieldSpec {
        name: "b0RootEnvelopeDigest",
        spec: RSpec::Digest("RootEnvelopeDigest"),
    },
    RFieldSpec {
        name: "b3ProfileEnvelopeDigest",
        spec: RSpec::Digest("B3ProfileEnvelopeDigest"),
    },
    RFieldSpec {
        name: "derivedGenesisStateDigest",
        spec: RSpec::Digest("B3StateDigest"),
    },
    RFieldSpec {
        name: "requestNonce",
        spec: RSpec::Bytes {
            exact: Some(32usize),
            maximum: None,
        },
    },
]);
const B3_INVALIDATION_ACK_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-b3-invalidation-ack"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "sessionId",
        spec: RSpec::Identifier { values: None },
    },
    RFieldSpec {
        name: "sequence",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 18446744073709551615u64,
        },
    },
    RFieldSpec {
        name: "frameEnvelopeDigest",
        spec: RSpec::Digest("B3InvalidationFrameEnvelopeDigest"),
    },
    RFieldSpec {
        name: "requestNonce",
        spec: RSpec::Bytes {
            exact: Some(32usize),
            maximum: None,
        },
    },
]);
const B3_INVALIDATION_FRAME_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "payload",
        spec: RSpec::Record(&[
            RFieldSpec {
                name: "schema",
                spec: RSpec::Identifier {
                    values: Some(&["keep.native-b3-invalidation"]),
                },
            },
            RFieldSpec {
                name: "version",
                spec: RSpec::Uint {
                    minimum: 1u64,
                    maximum: 1u64,
                },
            },
            RFieldSpec {
                name: "authorityId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "b3ProfileEnvelopeDigest",
                spec: RSpec::Digest("B3ProfileEnvelopeDigest"),
            },
            RFieldSpec {
                name: "scopeKey",
                spec: RSpec::Record(&[
                    RFieldSpec {
                        name: "authorityId",
                        spec: RSpec::Identifier { values: None },
                    },
                    RFieldSpec {
                        name: "namespace",
                        spec: RSpec::Identifier { values: None },
                    },
                    RFieldSpec {
                        name: "scope",
                        spec: RSpec::Identifier { values: None },
                    },
                    RFieldSpec {
                        name: "genesisRootDigest",
                        spec: RSpec::Digest("GenesisRootEnvelopeDigest"),
                    },
                ]),
            },
            RFieldSpec {
                name: "sessionId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "frameKind",
                spec: RSpec::Identifier {
                    values: Some(&["heartbeat", "invalidated"]),
                },
            },
            RFieldSpec {
                name: "sequence",
                spec: RSpec::Uint {
                    minimum: 1u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "priorGeneration",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "newGeneration",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "newStateDigest",
                spec: RSpec::Digest("B3StateDigest"),
            },
            RFieldSpec {
                name: "counter",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "requestNonce",
                spec: RSpec::Bytes {
                    exact: Some(32usize),
                    maximum: None,
                },
            },
            RFieldSpec {
                name: "priorAckDigest",
                spec: RSpec::Nullable(&RSpec::Digest("B3InvalidationAckDigest")),
            },
        ]),
    },
    RFieldSpec {
        name: "payloadDigest",
        spec: RSpec::Digest("PayloadDigest"),
    },
    RFieldSpec {
        name: "signatures",
        spec: RSpec::Array {
            item: &RSpec::Record(&[
                RFieldSpec {
                    name: "keyId",
                    spec: RSpec::Identifier { values: None },
                },
                RFieldSpec {
                    name: "algorithm",
                    spec: RSpec::Identifier {
                        values: Some(&["ed25519"]),
                    },
                },
                RFieldSpec {
                    name: "keyEpoch",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "signature",
                    spec: RSpec::Bytes {
                        exact: Some(64usize),
                        maximum: None,
                    },
                },
            ]),
            minimum: 1usize,
            maximum: 64usize,
            sorted_scalar: false,
            sort_by: &["keyId"],
            unique_by: &["keyId"],
        },
    },
]);
const B3_LEASE_OPERATION_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-b3-operation"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "operationKind",
        spec: RSpec::Identifier {
            values: Some(&["validate-lease"]),
        },
    },
    RFieldSpec {
        name: "scopeKey",
        spec: RSpec::Record(&[
            RFieldSpec {
                name: "authorityId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "namespace",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "scope",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "genesisRootDigest",
                spec: RSpec::Digest("GenesisRootEnvelopeDigest"),
            },
        ]),
    },
    RFieldSpec {
        name: "generation",
        spec: RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        },
    },
    RFieldSpec {
        name: "headEnvelopeDigest",
        spec: RSpec::Digest("RevocationEnvelopeDigest"),
    },
    RFieldSpec {
        name: "b3CounterCeiling",
        spec: RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        },
    },
    RFieldSpec {
        name: "requestNonce",
        spec: RSpec::Bytes {
            exact: Some(32usize),
            maximum: None,
        },
    },
]);
const B3_READ_OPERATION_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-b3-operation"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "operationKind",
        spec: RSpec::Identifier {
            values: Some(&["read"]),
        },
    },
    RFieldSpec {
        name: "scopeKey",
        spec: RSpec::Record(&[
            RFieldSpec {
                name: "authorityId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "namespace",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "scope",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "genesisRootDigest",
                spec: RSpec::Digest("GenesisRootEnvelopeDigest"),
            },
        ]),
    },
    RFieldSpec {
        name: "requestNonce",
        spec: RSpec::Bytes {
            exact: Some(32usize),
            maximum: None,
        },
    },
]);
const B3_RECEIPT_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "payload",
        spec: RSpec::Record(&[
            RFieldSpec {
                name: "schema",
                spec: RSpec::Identifier {
                    values: Some(&["keep.native-b3-receipt"]),
                },
            },
            RFieldSpec {
                name: "version",
                spec: RSpec::Uint {
                    minimum: 1u64,
                    maximum: 1u64,
                },
            },
            RFieldSpec {
                name: "operationKind",
                spec: RSpec::Identifier {
                    values: Some(&[
                        "genesis",
                        "read",
                        "compare-and-advance",
                        "validate-lease",
                        "subscribe-invalidation",
                    ]),
                },
            },
            RFieldSpec {
                name: "authorityId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "b3ProfileEnvelopeDigest",
                spec: RSpec::Digest("B3ProfileEnvelopeDigest"),
            },
            RFieldSpec {
                name: "scopeKey",
                spec: RSpec::Record(&[
                    RFieldSpec {
                        name: "authorityId",
                        spec: RSpec::Identifier { values: None },
                    },
                    RFieldSpec {
                        name: "namespace",
                        spec: RSpec::Identifier { values: None },
                    },
                    RFieldSpec {
                        name: "scope",
                        spec: RSpec::Identifier { values: None },
                    },
                    RFieldSpec {
                        name: "genesisRootDigest",
                        spec: RSpec::Digest("GenesisRootEnvelopeDigest"),
                    },
                ]),
            },
            RFieldSpec {
                name: "priorStateDigest",
                spec: RSpec::Digest("B3StateDigest"),
            },
            RFieldSpec {
                name: "newStateDigest",
                spec: RSpec::Digest("B3StateDigest"),
            },
            RFieldSpec {
                name: "operationDigest",
                spec: RSpec::Digest("B3OperationDigest"),
            },
            RFieldSpec {
                name: "requestNonce",
                spec: RSpec::Bytes {
                    exact: Some(32usize),
                    maximum: None,
                },
            },
            RFieldSpec {
                name: "generation",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "counter",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "committed",
                spec: RSpec::Boolean,
            },
            RFieldSpec {
                name: "keyId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "keyEpoch",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
        ]),
    },
    RFieldSpec {
        name: "payloadDigest",
        spec: RSpec::Digest("PayloadDigest"),
    },
    RFieldSpec {
        name: "signatures",
        spec: RSpec::Array {
            item: &RSpec::Record(&[
                RFieldSpec {
                    name: "keyId",
                    spec: RSpec::Identifier { values: None },
                },
                RFieldSpec {
                    name: "algorithm",
                    spec: RSpec::Identifier {
                        values: Some(&["ed25519"]),
                    },
                },
                RFieldSpec {
                    name: "keyEpoch",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "signature",
                    spec: RSpec::Bytes {
                        exact: Some(64usize),
                        maximum: None,
                    },
                },
            ]),
            minimum: 1usize,
            maximum: 64usize,
            sorted_scalar: false,
            sort_by: &["keyId"],
            unique_by: &["keyId"],
        },
    },
]);
const B3_STATE_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "scopeKey",
        spec: RSpec::Record(&[
            RFieldSpec {
                name: "authorityId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "namespace",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "scope",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "genesisRootDigest",
                spec: RSpec::Digest("GenesisRootEnvelopeDigest"),
            },
        ]),
    },
    RFieldSpec {
        name: "generation",
        spec: RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        },
    },
    RFieldSpec {
        name: "rootEpoch",
        spec: RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        },
    },
    RFieldSpec {
        name: "rootEnvelopeDigest",
        spec: RSpec::Digest("RootEnvelopeDigest"),
    },
    RFieldSpec {
        name: "b3ProfileEnvelopeDigest",
        spec: RSpec::Digest("B3ProfileEnvelopeDigest"),
    },
    RFieldSpec {
        name: "headSequence",
        spec: RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        },
    },
    RFieldSpec {
        name: "headEnvelopeDigest",
        spec: RSpec::Digest("RevocationEnvelopeDigest"),
    },
    RFieldSpec {
        name: "deploymentEpoch",
        spec: RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        },
    },
    RFieldSpec {
        name: "artifactFloor",
        spec: RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        },
    },
    RFieldSpec {
        name: "counter",
        spec: RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        },
    },
    RFieldSpec {
        name: "quarantined",
        spec: RSpec::Boolean,
    },
    RFieldSpec {
        name: "quarantineDigest",
        spec: RSpec::Digest("QuarantineDigest"),
    },
    RFieldSpec {
        name: "consumedAuthorization",
        spec: RSpec::Nullable(&RSpec::Tagged {
            tag: "kind",
            variants: &[
                VariantSpec {
                    name: "rollback",
                    spec: RSpec::Record(&[
                        RFieldSpec {
                            name: "kind",
                            spec: RSpec::Identifier {
                                values: Some(&["rollback"]),
                            },
                        },
                        RFieldSpec {
                            name: "authorizationEnvelopeDigest",
                            spec: RSpec::Digest("RollbackAuthorizationEnvelopeDigest"),
                        },
                    ]),
                },
                VariantSpec {
                    name: "recovery",
                    spec: RSpec::Record(&[
                        RFieldSpec {
                            name: "kind",
                            spec: RSpec::Identifier {
                                values: Some(&["recovery"]),
                            },
                        },
                        RFieldSpec {
                            name: "authorizationEnvelopeDigest",
                            spec: RSpec::Digest("RevocationRecoveryEnvelopeDigest"),
                        },
                    ]),
                },
            ],
        }),
    },
]);
const B3_SUBSCRIBE_OPERATION_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-b3-operation"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "operationKind",
        spec: RSpec::Identifier {
            values: Some(&["subscribe-invalidation"]),
        },
    },
    RFieldSpec {
        name: "scopeKey",
        spec: RSpec::Record(&[
            RFieldSpec {
                name: "authorityId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "namespace",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "scope",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "genesisRootDigest",
                spec: RSpec::Digest("GenesisRootEnvelopeDigest"),
            },
        ]),
    },
    RFieldSpec {
        name: "generation",
        spec: RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        },
    },
    RFieldSpec {
        name: "sessionId",
        spec: RSpec::Identifier { values: None },
    },
    RFieldSpec {
        name: "requestNonce",
        spec: RSpec::Bytes {
            exact: Some(32usize),
            maximum: None,
        },
    },
]);
const NATIVE_ARTIFACT_INVENTORY_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-artifact-inventory"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "buildId",
        spec: RSpec::Identifier { values: None },
    },
    RFieldSpec {
        name: "targetTriple",
        spec: RSpec::Identifier { values: None },
    },
    RFieldSpec {
        name: "variant",
        spec: RSpec::Identifier { values: None },
    },
    RFieldSpec {
        name: "rows",
        spec: RSpec::Array {
            item: &RSpec::Record(&[
                RFieldSpec {
                    name: "artifactId",
                    spec: RSpec::Identifier { values: None },
                },
                RFieldSpec {
                    name: "kind",
                    spec: RSpec::Identifier {
                        values: Some(&[
                            "helper",
                            "trampoline",
                            "role",
                            "prober",
                            "provisioner",
                            "policy",
                            "evidence-schema",
                        ]),
                    },
                },
                RFieldSpec {
                    name: "digest",
                    spec: RSpec::Digest("ArtifactFileDigest"),
                },
                RFieldSpec {
                    name: "size",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "mode",
                    spec: RSpec::Identifier {
                        values: Some(&["0444", "0555"]),
                    },
                },
                RFieldSpec {
                    name: "targetTriple",
                    spec: RSpec::Identifier { values: None },
                },
                RFieldSpec {
                    name: "variant",
                    spec: RSpec::Identifier { values: None },
                },
                RFieldSpec {
                    name: "releaseMember",
                    spec: RSpec::Boolean,
                },
            ]),
            minimum: 0usize,
            maximum: 256usize,
            sorted_scalar: false,
            sort_by: &["artifactId"],
            unique_by: &["artifactId"],
        },
    },
]);
const NATIVE_B3_GENESIS_BASE_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-b3-genesis-base"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "trustClass",
        spec: RSpec::Identifier {
            values: Some(&["production", "development"]),
        },
    },
    RFieldSpec {
        name: "authorityId",
        spec: RSpec::Identifier { values: None },
    },
    RFieldSpec {
        name: "namespace",
        spec: RSpec::Identifier { values: None },
    },
    RFieldSpec {
        name: "scope",
        spec: RSpec::Identifier { values: None },
    },
    RFieldSpec {
        name: "headSequence",
        spec: RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        },
    },
    RFieldSpec {
        name: "headEnvelopeDigest",
        spec: RSpec::Digest("RevocationEnvelopeDigest"),
    },
    RFieldSpec {
        name: "deploymentEpoch",
        spec: RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        },
    },
    RFieldSpec {
        name: "artifactFloor",
        spec: RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        },
    },
    RFieldSpec {
        name: "counter",
        spec: RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        },
    },
]);
const NATIVE_B3_PROFILE_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "payload",
        spec: RSpec::Record(&[
            RFieldSpec {
                name: "schema",
                spec: RSpec::Identifier {
                    values: Some(&["keep.native-b3-profile"]),
                },
            },
            RFieldSpec {
                name: "version",
                spec: RSpec::Uint {
                    minimum: 1u64,
                    maximum: 1u64,
                },
            },
            RFieldSpec {
                name: "trustClass",
                spec: RSpec::Identifier {
                    values: Some(&["production", "development"]),
                },
            },
            RFieldSpec {
                name: "authorityId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "b0RootEnvelopeDigest",
                spec: RSpec::Digest("RootEnvelopeDigest"),
            },
            RFieldSpec {
                name: "genesisBaseDigest",
                spec: RSpec::Digest("GenesisBaseDigest"),
            },
            RFieldSpec {
                name: "predecessorProfileEnvelopeDigest",
                spec: RSpec::Nullable(&RSpec::Digest("B3ProfileEnvelopeDigest")),
            },
            RFieldSpec {
                name: "algorithm",
                spec: RSpec::Identifier {
                    values: Some(&["ed25519"]),
                },
            },
            RFieldSpec {
                name: "keyId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "keyEpoch",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "publicKey",
                spec: RSpec::Bytes {
                    exact: Some(32usize),
                    maximum: None,
                },
            },
            RFieldSpec {
                name: "validFromCounter",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "validUntilCounter",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "transportIdentityDigest",
                spec: RSpec::Digest("TransportIdentityDigest"),
            },
            RFieldSpec {
                name: "maxHeartbeatIntervalMs",
                spec: RSpec::Uint {
                    minimum: 1u64,
                    maximum: 1000u64,
                },
            },
        ]),
    },
    RFieldSpec {
        name: "payloadDigest",
        spec: RSpec::Digest("PayloadDigest"),
    },
    RFieldSpec {
        name: "signatures",
        spec: RSpec::Array {
            item: &RSpec::Record(&[
                RFieldSpec {
                    name: "keyId",
                    spec: RSpec::Identifier { values: None },
                },
                RFieldSpec {
                    name: "algorithm",
                    spec: RSpec::Identifier {
                        values: Some(&["ed25519"]),
                    },
                },
                RFieldSpec {
                    name: "keyEpoch",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "signature",
                    spec: RSpec::Bytes {
                        exact: Some(64usize),
                        maximum: None,
                    },
                },
            ]),
            minimum: 1usize,
            maximum: 64usize,
            sorted_scalar: false,
            sort_by: &["keyId"],
            unique_by: &["keyId"],
        },
    },
]);
const NATIVE_BUILD_COMMAND_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-build-command"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "executableDigest",
        spec: RSpec::Digest("BuildToolDigest"),
    },
    RFieldSpec {
        name: "arguments",
        spec: RSpec::Array {
            item: &RSpec::Text {
                values: None,
                pattern: None,
            },
            minimum: 0usize,
            maximum: 256usize,
            sorted_scalar: false,
            sort_by: &[],
            unique_by: &[],
        },
    },
]);
const NATIVE_BUILD_IDENTITY_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "payload",
        spec: RSpec::Record(&[
            RFieldSpec {
                name: "schema",
                spec: RSpec::Identifier {
                    values: Some(&["keep.native-build-identity"]),
                },
            },
            RFieldSpec {
                name: "version",
                spec: RSpec::Uint {
                    minimum: 1u64,
                    maximum: 1u64,
                },
            },
            RFieldSpec {
                name: "trustClass",
                spec: RSpec::Identifier {
                    values: Some(&["production", "development"]),
                },
            },
            RFieldSpec {
                name: "identityKind",
                spec: RSpec::Identifier {
                    values: Some(&["builder", "comparer"]),
                },
            },
            RFieldSpec {
                name: "identityId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "administrativeDomain",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "toolchainLineageDigest",
                spec: RSpec::Digest("ToolchainLineageDigest"),
            },
            RFieldSpec {
                name: "keyId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "keyEpoch",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "publicKey",
                spec: RSpec::Bytes {
                    exact: Some(32usize),
                    maximum: None,
                },
            },
            RFieldSpec {
                name: "validFromCounter",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "validUntilCounter",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
        ]),
    },
    RFieldSpec {
        name: "payloadDigest",
        spec: RSpec::Digest("PayloadDigest"),
    },
    RFieldSpec {
        name: "signatures",
        spec: RSpec::Array {
            item: &RSpec::Record(&[
                RFieldSpec {
                    name: "keyId",
                    spec: RSpec::Identifier { values: None },
                },
                RFieldSpec {
                    name: "algorithm",
                    spec: RSpec::Identifier {
                        values: Some(&["ed25519"]),
                    },
                },
                RFieldSpec {
                    name: "keyEpoch",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "signature",
                    spec: RSpec::Bytes {
                        exact: Some(64usize),
                        maximum: None,
                    },
                },
            ]),
            minimum: 1usize,
            maximum: 64usize,
            sorted_scalar: false,
            sort_by: &["keyId"],
            unique_by: &["keyId"],
        },
    },
]);
const NATIVE_COMPARISON_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-comparison"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "algorithm",
        spec: RSpec::Identifier {
            values: Some(&["sha256-byte-for-byte/v1"]),
        },
    },
    RFieldSpec {
        name: "leftSubjectDigest",
        spec: RSpec::Digest("SubjectDigest"),
    },
    RFieldSpec {
        name: "rightSubjectDigest",
        spec: RSpec::Digest("SubjectDigest"),
    },
    RFieldSpec {
        name: "disagreementsDigest",
        spec: RSpec::Digest("DisagreementsDigest"),
    },
]);
const NATIVE_CONTROL_POLICY_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-control-policy"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "controlId",
        spec: RSpec::Identifier { values: None },
    },
    RFieldSpec {
        name: "decisionClass",
        spec: RSpec::Identifier {
            values: Some(&["permit", "deny", "measure-only"]),
        },
    },
    RFieldSpec {
        name: "requirements",
        spec: RSpec::Array {
            item: &RSpec::Identifier {
                values: Some(&[
                    "signature-valid",
                    "threshold-met",
                    "content-address-match",
                    "subject-match",
                    "fresh",
                    "not-revoked",
                    "floor-satisfied",
                    "lease-active",
                    "isolation-measured",
                ]),
            },
            minimum: 0usize,
            maximum: 256usize,
            sorted_scalar: true,
            sort_by: &[],
            unique_by: &[],
        },
    },
]);
const NATIVE_CONTROL_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-control"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "controlId",
        spec: RSpec::Identifier { values: None },
    },
    RFieldSpec {
        name: "subjectDigest",
        spec: RSpec::Digest("SubjectDigest"),
    },
    RFieldSpec {
        name: "policyDigest",
        spec: RSpec::Digest("ControlPolicyDigest"),
    },
]);
const NATIVE_ENVIRONMENT_POLICY_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-environment-policy"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "allowedVariables",
        spec: RSpec::Array {
            item: &RSpec::Identifier { values: None },
            minimum: 0usize,
            maximum: 256usize,
            sorted_scalar: true,
            sort_by: &[],
            unique_by: &[],
        },
    },
    RFieldSpec {
        name: "workingDirectoryPolicy",
        spec: RSpec::Identifier {
            values: Some(&["empty", "fixed-source-root"]),
        },
    },
    RFieldSpec {
        name: "networkPolicy",
        spec: RSpec::Identifier {
            values: Some(&["denied", "builder-isolated"]),
        },
    },
]);
const NATIVE_FD_FLAGS_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-fd-flags"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "flags",
        spec: RSpec::Array {
            item: &RSpec::Identifier {
                values: Some(&[
                    "O_RDONLY",
                    "O_CLOEXEC",
                    "O_NOFOLLOW",
                    "O_PATH",
                    "O_DIRECTORY",
                ]),
            },
            minimum: 0usize,
            maximum: 5usize,
            sorted_scalar: true,
            sort_by: &[],
            unique_by: &[],
        },
    },
    RFieldSpec {
        name: "closeOnExec",
        spec: RSpec::Boolean,
    },
    RFieldSpec {
        name: "seals",
        spec: RSpec::Array {
            item: &RSpec::Identifier {
                values: Some(&[
                    "F_SEAL_WRITE",
                    "F_SEAL_SHRINK",
                    "F_SEAL_GROW",
                    "F_SEAL_EXEC",
                    "F_SEAL_SEAL",
                ]),
            },
            minimum: 0usize,
            maximum: 5usize,
            sorted_scalar: true,
            sort_by: &[],
            unique_by: &[],
        },
    },
]);
const NATIVE_GENESIS_EPOCH_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-genesis-epoch"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "trustClass",
        spec: RSpec::Identifier {
            values: Some(&["production", "development"]),
        },
    },
    RFieldSpec {
        name: "rootId",
        spec: RSpec::Identifier { values: None },
    },
    RFieldSpec {
        name: "rootKeys",
        spec: RSpec::Array {
            item: &RSpec::Record(&[
                RFieldSpec {
                    name: "keyId",
                    spec: RSpec::Identifier { values: None },
                },
                RFieldSpec {
                    name: "algorithm",
                    spec: RSpec::Identifier {
                        values: Some(&["ed25519"]),
                    },
                },
                RFieldSpec {
                    name: "publicKey",
                    spec: RSpec::Bytes {
                        exact: Some(32usize),
                        maximum: None,
                    },
                },
                RFieldSpec {
                    name: "keyEpoch",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "validFromCounter",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "validUntilCounter",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
            ]),
            minimum: 1usize,
            maximum: 32usize,
            sorted_scalar: false,
            sort_by: &["keyId"],
            unique_by: &["keyId"],
        },
    },
    RFieldSpec {
        name: "rootThreshold",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 32u64,
        },
    },
    RFieldSpec {
        name: "participantIds",
        spec: RSpec::Array {
            item: &RSpec::Identifier { values: None },
            minimum: 1usize,
            maximum: 64usize,
            sorted_scalar: true,
            sort_by: &[],
            unique_by: &[],
        },
    },
    RFieldSpec {
        name: "minimumParticipants",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 64u64,
        },
    },
    RFieldSpec {
        name: "requiredOffline",
        spec: RSpec::Boolean,
    },
    RFieldSpec {
        name: "requiredWitnesses",
        spec: RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        },
    },
    RFieldSpec {
        name: "issuedCounter",
        spec: RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        },
    },
    RFieldSpec {
        name: "nonce",
        spec: RSpec::Bytes {
            exact: Some(32usize),
            maximum: None,
        },
    },
]);
const NATIVE_INVOCATION_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-invocation"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "buildId",
        spec: RSpec::Identifier { values: None },
    },
    RFieldSpec {
        name: "commandDigest",
        spec: RSpec::Digest("BuildCommandDigest"),
    },
    RFieldSpec {
        name: "environmentPolicyDigest",
        spec: RSpec::Digest("EnvironmentPolicyDigest"),
    },
    RFieldSpec {
        name: "inputs",
        spec: RSpec::Array {
            item: &RSpec::Record(&[
                RFieldSpec {
                    name: "uri",
                    spec: RSpec::Text {
                        values: None,
                        pattern: Some("^(?:keep-artifact:|keep-source:|oci:)[A-Za-z0-9._:/+@-]+$"),
                    },
                },
                RFieldSpec {
                    name: "artifactDigest",
                    spec: RSpec::Digest("InvocationInputArtifactDigest"),
                },
            ]),
            minimum: 0usize,
            maximum: 4096usize,
            sorted_scalar: false,
            sort_by: &["uri"],
            unique_by: &["uri"],
        },
    },
]);
const NATIVE_IO_MAX_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-io-max"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "defaultPolicy",
        spec: RSpec::Identifier {
            values: Some(&["deny-unlisted"]),
        },
    },
    RFieldSpec {
        name: "rows",
        spec: RSpec::Array {
            item: &RSpec::Record(&[
                RFieldSpec {
                    name: "deviceMajor",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "deviceMinor",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "readBytesPerSecond",
                    spec: RSpec::Nullable(&RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    }),
                },
                RFieldSpec {
                    name: "writeBytesPerSecond",
                    spec: RSpec::Nullable(&RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    }),
                },
                RFieldSpec {
                    name: "readIops",
                    spec: RSpec::Nullable(&RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    }),
                },
                RFieldSpec {
                    name: "writeIops",
                    spec: RSpec::Nullable(&RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    }),
                },
            ]),
            minimum: 0usize,
            maximum: 128usize,
            sorted_scalar: false,
            sort_by: &["deviceMajor", "deviceMinor"],
            unique_by: &["deviceMajor", "deviceMinor"],
        },
    },
]);
const NATIVE_JOURNAL_ENTRIES_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-journal-entries"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "entries",
        spec: RSpec::Array {
            item: &RSpec::Record(&[
                RFieldSpec {
                    name: "sequence",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "eventCode",
                    spec: RSpec::Identifier { values: None },
                },
                RFieldSpec {
                    name: "subjectDigest",
                    spec: RSpec::Digest("JournalSubjectDigest"),
                },
                RFieldSpec {
                    name: "counter",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
            ]),
            minimum: 0usize,
            maximum: 4096usize,
            sorted_scalar: false,
            sort_by: &["sequence"],
            unique_by: &["sequence"],
        },
    },
]);
const NATIVE_JOURNAL_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-journal"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "deploymentId",
        spec: RSpec::Identifier { values: None },
    },
    RFieldSpec {
        name: "bootId",
        spec: RSpec::Identifier { values: None },
    },
    RFieldSpec {
        name: "sequence",
        spec: RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        },
    },
    RFieldSpec {
        name: "previousJournalDigest",
        spec: RSpec::Digest("JournalDigest"),
    },
    RFieldSpec {
        name: "entriesDigest",
        spec: RSpec::Digest("JournalEntriesDigest"),
    },
]);
const NATIVE_LANDLOCK_POLICY_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-landlock-policy"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "minimumAbi",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 255u64,
        },
    },
    RFieldSpec {
        name: "handledFilesystemRights",
        spec: RSpec::Array {
            item: &RSpec::Identifier {
                values: Some(&[
                    "execute",
                    "write-file",
                    "read-file",
                    "read-dir",
                    "remove-dir",
                    "remove-file",
                    "make-char",
                    "make-dir",
                    "make-reg",
                    "make-sock",
                    "make-fifo",
                    "make-block",
                    "make-sym",
                    "refer",
                    "truncate",
                    "ioctl-dev",
                ]),
            },
            minimum: 0usize,
            maximum: 16usize,
            sorted_scalar: true,
            sort_by: &[],
            unique_by: &[],
        },
    },
    RFieldSpec {
        name: "handledNetworkRights",
        spec: RSpec::Array {
            item: &RSpec::Identifier {
                values: Some(&["bind-tcp", "connect-tcp"]),
            },
            minimum: 0usize,
            maximum: 2usize,
            sorted_scalar: true,
            sort_by: &[],
            unique_by: &[],
        },
    },
    RFieldSpec {
        name: "handledScopeRights",
        spec: RSpec::Array {
            item: &RSpec::Identifier {
                values: Some(&["signal", "abstract-unix-socket"]),
            },
            minimum: 0usize,
            maximum: 2usize,
            sorted_scalar: true,
            sort_by: &[],
            unique_by: &[],
        },
    },
    RFieldSpec {
        name: "rules",
        spec: RSpec::Array {
            item: &RSpec::Tagged {
                tag: "kind",
                variants: &[
                    VariantSpec {
                        name: "path-beneath",
                        spec: RSpec::Record(&[
                            RFieldSpec {
                                name: "kind",
                                spec: RSpec::Identifier {
                                    values: Some(&["path-beneath"]),
                                },
                            },
                            RFieldSpec {
                                name: "path",
                                spec: RSpec::Text {
                                    values: None,
                                    pattern: Some(
                                        "^(?!.*(?:^|\\/)\\.\\.?(?:\\/|$))\\/(?:[A-Za-z0-9._+-]+(?:\\/[A-Za-z0-9._+-]+)*)?$",
                                    ),
                                },
                            },
                            RFieldSpec {
                                name: "accessRights",
                                spec: RSpec::Array {
                                    item: &RSpec::Identifier {
                                        values: Some(&[
                                            "execute",
                                            "write-file",
                                            "read-file",
                                            "read-dir",
                                            "remove-dir",
                                            "remove-file",
                                            "make-char",
                                            "make-dir",
                                            "make-reg",
                                            "make-sock",
                                            "make-fifo",
                                            "make-block",
                                            "make-sym",
                                            "refer",
                                            "truncate",
                                            "ioctl-dev",
                                        ]),
                                    },
                                    minimum: 0usize,
                                    maximum: 16usize,
                                    sorted_scalar: true,
                                    sort_by: &[],
                                    unique_by: &[],
                                },
                            },
                        ]),
                    },
                    VariantSpec {
                        name: "tcp-port",
                        spec: RSpec::Record(&[
                            RFieldSpec {
                                name: "kind",
                                spec: RSpec::Identifier {
                                    values: Some(&["tcp-port"]),
                                },
                            },
                            RFieldSpec {
                                name: "port",
                                spec: RSpec::Uint {
                                    minimum: 1u64,
                                    maximum: 65535u64,
                                },
                            },
                            RFieldSpec {
                                name: "accessRights",
                                spec: RSpec::Array {
                                    item: &RSpec::Identifier {
                                        values: Some(&["bind-tcp", "connect-tcp"]),
                                    },
                                    minimum: 0usize,
                                    maximum: 2usize,
                                    sorted_scalar: true,
                                    sort_by: &[],
                                    unique_by: &[],
                                },
                            },
                        ]),
                    },
                ],
            },
            minimum: 0usize,
            maximum: 256usize,
            sorted_scalar: false,
            sort_by: &[],
            unique_by: &[],
        },
    },
]);
const NATIVE_LANDLOCK_POLICY_V2_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-landlock-policy"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 2u64,
            maximum: 2u64,
        },
    },
    RFieldSpec {
        name: "minimumAbi",
        spec: RSpec::Uint {
            minimum: 4u64,
            maximum: 10u64,
        },
    },
    RFieldSpec {
        name: "effectiveAbi",
        spec: RSpec::Uint {
            minimum: 4u64,
            maximum: 10u64,
        },
    },
    RFieldSpec {
        name: "reviewedMaximumAbi",
        spec: RSpec::Uint {
            minimum: 10u64,
            maximum: 10u64,
        },
    },
    RFieldSpec {
        name: "handledFilesystemRights",
        spec: RSpec::Array {
            item: &RSpec::Identifier {
                values: Some(&[
                    "execute",
                    "write-file",
                    "read-file",
                    "read-dir",
                    "remove-dir",
                    "remove-file",
                    "make-char",
                    "make-dir",
                    "make-reg",
                    "make-sock",
                    "make-fifo",
                    "make-block",
                    "make-sym",
                    "refer",
                    "truncate",
                    "ioctl-dev",
                    "resolve-unix",
                ]),
            },
            minimum: 0usize,
            maximum: 17usize,
            sorted_scalar: true,
            sort_by: &[],
            unique_by: &[],
        },
    },
    RFieldSpec {
        name: "handledNetworkRights",
        spec: RSpec::Array {
            item: &RSpec::Identifier {
                values: Some(&["bind-tcp", "connect-tcp", "bind-udp", "connect-send-udp"]),
            },
            minimum: 0usize,
            maximum: 4usize,
            sorted_scalar: true,
            sort_by: &[],
            unique_by: &[],
        },
    },
    RFieldSpec {
        name: "handledScopeRights",
        spec: RSpec::Array {
            item: &RSpec::Identifier {
                values: Some(&["signal", "abstract-unix-socket"]),
            },
            minimum: 0usize,
            maximum: 2usize,
            sorted_scalar: true,
            sort_by: &[],
            unique_by: &[],
        },
    },
    RFieldSpec {
        name: "rules",
        spec: RSpec::Array {
            item: &RSpec::Tagged {
                tag: "kind",
                variants: &[
                    VariantSpec {
                        name: "path-beneath",
                        spec: RSpec::Record(&[
                            RFieldSpec {
                                name: "kind",
                                spec: RSpec::Identifier {
                                    values: Some(&["path-beneath"]),
                                },
                            },
                            RFieldSpec {
                                name: "path",
                                spec: RSpec::Text {
                                    values: None,
                                    pattern: Some(
                                        "^(?!.*(?:^|\\/)\\.\\.?(?:\\/|$))\\/(?:[A-Za-z0-9._+-]+(?:\\/[A-Za-z0-9._+-]+)*)?$",
                                    ),
                                },
                            },
                            RFieldSpec {
                                name: "accessRights",
                                spec: RSpec::Array {
                                    item: &RSpec::Identifier {
                                        values: Some(&[
                                            "execute",
                                            "write-file",
                                            "read-file",
                                            "read-dir",
                                            "remove-dir",
                                            "remove-file",
                                            "make-char",
                                            "make-dir",
                                            "make-reg",
                                            "make-sock",
                                            "make-fifo",
                                            "make-block",
                                            "make-sym",
                                            "refer",
                                            "truncate",
                                            "ioctl-dev",
                                            "resolve-unix",
                                        ]),
                                    },
                                    minimum: 0usize,
                                    maximum: 17usize,
                                    sorted_scalar: true,
                                    sort_by: &[],
                                    unique_by: &[],
                                },
                            },
                        ]),
                    },
                    VariantSpec {
                        name: "tcp-port",
                        spec: RSpec::Record(&[
                            RFieldSpec {
                                name: "kind",
                                spec: RSpec::Identifier {
                                    values: Some(&["tcp-port"]),
                                },
                            },
                            RFieldSpec {
                                name: "port",
                                spec: RSpec::Uint {
                                    minimum: 1u64,
                                    maximum: 65535u64,
                                },
                            },
                            RFieldSpec {
                                name: "accessRights",
                                spec: RSpec::Array {
                                    item: &RSpec::Identifier {
                                        values: Some(&["bind-tcp", "connect-tcp"]),
                                    },
                                    minimum: 0usize,
                                    maximum: 2usize,
                                    sorted_scalar: true,
                                    sort_by: &[],
                                    unique_by: &[],
                                },
                            },
                        ]),
                    },
                    VariantSpec {
                        name: "udp-port",
                        spec: RSpec::Record(&[
                            RFieldSpec {
                                name: "kind",
                                spec: RSpec::Identifier {
                                    values: Some(&["udp-port"]),
                                },
                            },
                            RFieldSpec {
                                name: "port",
                                spec: RSpec::Uint {
                                    minimum: 0u64,
                                    maximum: 65535u64,
                                },
                            },
                            RFieldSpec {
                                name: "accessRights",
                                spec: RSpec::Array {
                                    item: &RSpec::Identifier {
                                        values: Some(&["bind-udp", "connect-send-udp"]),
                                    },
                                    minimum: 0usize,
                                    maximum: 2usize,
                                    sorted_scalar: true,
                                    sort_by: &[],
                                    unique_by: &[],
                                },
                            },
                        ]),
                    },
                ],
            },
            minimum: 0usize,
            maximum: 256usize,
            sorted_scalar: false,
            sort_by: &[],
            unique_by: &[],
        },
    },
]);
const NATIVE_OBSERVATION_RESULT_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-observation-result"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "resultCode",
        spec: RSpec::Identifier {
            values: Some(&["pass", "fail", "inconclusive"]),
        },
    },
    RFieldSpec {
        name: "facts",
        spec: RSpec::Array {
            item: &RSpec::Tagged {
                tag: "valueType",
                variants: &[
                    VariantSpec {
                        name: "identifier",
                        spec: RSpec::Record(&[
                            RFieldSpec {
                                name: "factId",
                                spec: RSpec::Identifier { values: None },
                            },
                            RFieldSpec {
                                name: "valueType",
                                spec: RSpec::Identifier {
                                    values: Some(&["identifier"]),
                                },
                            },
                            RFieldSpec {
                                name: "value",
                                spec: RSpec::Identifier { values: None },
                            },
                        ]),
                    },
                    VariantSpec {
                        name: "uint64",
                        spec: RSpec::Record(&[
                            RFieldSpec {
                                name: "factId",
                                spec: RSpec::Identifier { values: None },
                            },
                            RFieldSpec {
                                name: "valueType",
                                spec: RSpec::Identifier {
                                    values: Some(&["uint64"]),
                                },
                            },
                            RFieldSpec {
                                name: "value",
                                spec: RSpec::Uint {
                                    minimum: 0u64,
                                    maximum: 18446744073709551615u64,
                                },
                            },
                        ]),
                    },
                    VariantSpec {
                        name: "boolean",
                        spec: RSpec::Record(&[
                            RFieldSpec {
                                name: "factId",
                                spec: RSpec::Identifier { values: None },
                            },
                            RFieldSpec {
                                name: "valueType",
                                spec: RSpec::Identifier {
                                    values: Some(&["boolean"]),
                                },
                            },
                            RFieldSpec {
                                name: "value",
                                spec: RSpec::Boolean,
                            },
                        ]),
                    },
                ],
            },
            minimum: 0usize,
            maximum: 1024usize,
            sorted_scalar: false,
            sort_by: &["factId"],
            unique_by: &["factId"],
        },
    },
]);
const NATIVE_PACKAGE_PAYLOAD_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-package-payload"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "buildId",
        spec: RSpec::Identifier { values: None },
    },
    RFieldSpec {
        name: "targetTriple",
        spec: RSpec::Identifier { values: None },
    },
    RFieldSpec {
        name: "variant",
        spec: RSpec::Identifier { values: None },
    },
    RFieldSpec {
        name: "nativeArtifactInventoryDigest",
        spec: RSpec::Digest("NativeArtifactInventoryDigest"),
    },
    RFieldSpec {
        name: "members",
        spec: RSpec::Array {
            item: &RSpec::Record(&[
                RFieldSpec {
                    name: "installRoot",
                    spec: RSpec::Identifier {
                        values: Some(&[
                            "artifacts",
                            "policy",
                            "evidence-schema",
                            "inventory",
                            "toolchain",
                        ]),
                    },
                },
                RFieldSpec {
                    name: "relativePath",
                    spec: RSpec::Text {
                        values: None,
                        pattern: Some(
                            "^(?!\\/)(?!.*(?:^|\\/)\\.\\.?(?:\\/|$))(?!.*\\/\\/)[A-Za-z0-9._+-]+(?:\\/[A-Za-z0-9._+-]+)*$",
                        ),
                    },
                },
                RFieldSpec {
                    name: "digest",
                    spec: RSpec::Digest("PackageMemberDigest"),
                },
                RFieldSpec {
                    name: "size",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "mode",
                    spec: RSpec::Identifier {
                        values: Some(&["0444", "0555"]),
                    },
                },
                RFieldSpec {
                    name: "ownerUid",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "ownerGid",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "objectType",
                    spec: RSpec::Identifier {
                        values: Some(&["regular-executable", "regular-data"]),
                    },
                },
            ]),
            minimum: 0usize,
            maximum: 4096usize,
            sorted_scalar: false,
            sort_by: &["installRoot", "relativePath"],
            unique_by: &["installRoot", "relativePath"],
        },
    },
]);
const NATIVE_PEER_POLICY_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-peer-policy"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "requiredUid",
        spec: RSpec::Nullable(&RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        }),
    },
    RFieldSpec {
        name: "requiredGid",
        spec: RSpec::Nullable(&RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        }),
    },
    RFieldSpec {
        name: "requiredSecurityLabel",
        spec: RSpec::Nullable(&RSpec::Identifier { values: None }),
    },
]);
const NATIVE_PROVENANCE_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "payload",
        spec: RSpec::Record(&[
            RFieldSpec {
                name: "schema",
                spec: RSpec::Identifier {
                    values: Some(&["keep.native-provenance"]),
                },
            },
            RFieldSpec {
                name: "version",
                spec: RSpec::Uint {
                    minimum: 1u64,
                    maximum: 1u64,
                },
            },
            RFieldSpec {
                name: "builderId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "builderIdentityEnvelopeDigest",
                spec: RSpec::Digest("BuilderIdentityEnvelopeDigest"),
            },
            RFieldSpec {
                name: "buildType",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "buildId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "targetTriple",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "variant",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "nativeArtifactInventoryDigest",
                spec: RSpec::Digest("NativeArtifactInventoryDigest"),
            },
            RFieldSpec {
                name: "nativePackagePayloadDigest",
                spec: RSpec::Digest("NativePackagePayloadDigest"),
            },
            RFieldSpec {
                name: "toolchainClosureEnvelopeDigest",
                spec: RSpec::Digest("ToolchainClosureEnvelopeDigest"),
            },
            RFieldSpec {
                name: "invocationDigest",
                spec: RSpec::Digest("InvocationDigest"),
            },
            RFieldSpec {
                name: "materials",
                spec: RSpec::Array {
                    item: &RSpec::Record(&[
                        RFieldSpec {
                            name: "uri",
                            spec: RSpec::Text {
                                values: None,
                                pattern: Some(
                                    "^(?:keep-artifact:|keep-source:|oci:)[A-Za-z0-9._:/+@-]+$",
                                ),
                            },
                        },
                        RFieldSpec {
                            name: "digestType",
                            spec: RSpec::Identifier {
                                values: Some(&[
                                    "ArtifactDigest",
                                    "SourceDigest",
                                    "OciBlobDigest",
                                    "SubjectDigest",
                                ]),
                            },
                        },
                        RFieldSpec {
                            name: "digest",
                            spec: RSpec::Digest("MaterialDigest"),
                        },
                    ]),
                    minimum: 0usize,
                    maximum: 8192usize,
                    sorted_scalar: false,
                    sort_by: &["uri"],
                    unique_by: &["uri"],
                },
            },
            RFieldSpec {
                name: "subjects",
                spec: RSpec::Array {
                    item: &RSpec::Record(&[
                        RFieldSpec {
                            name: "uri",
                            spec: RSpec::Text {
                                values: None,
                                pattern: Some(
                                    "^(?:keep-artifact:|keep-source:|oci:)[A-Za-z0-9._:/+@-]+$",
                                ),
                            },
                        },
                        RFieldSpec {
                            name: "digestType",
                            spec: RSpec::Identifier {
                                values: Some(&[
                                    "ArtifactDigest",
                                    "SourceDigest",
                                    "OciBlobDigest",
                                    "SubjectDigest",
                                ]),
                            },
                        },
                        RFieldSpec {
                            name: "digest",
                            spec: RSpec::Digest("MaterialDigest"),
                        },
                    ]),
                    minimum: 0usize,
                    maximum: 4096usize,
                    sorted_scalar: false,
                    sort_by: &["uri"],
                    unique_by: &["uri"],
                },
            },
            RFieldSpec {
                name: "startedCounter",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "finishedCounter",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
        ]),
    },
    RFieldSpec {
        name: "payloadDigest",
        spec: RSpec::Digest("PayloadDigest"),
    },
    RFieldSpec {
        name: "signatures",
        spec: RSpec::Array {
            item: &RSpec::Record(&[
                RFieldSpec {
                    name: "keyId",
                    spec: RSpec::Identifier { values: None },
                },
                RFieldSpec {
                    name: "algorithm",
                    spec: RSpec::Identifier {
                        values: Some(&["ed25519"]),
                    },
                },
                RFieldSpec {
                    name: "keyEpoch",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "signature",
                    spec: RSpec::Bytes {
                        exact: Some(64usize),
                        maximum: None,
                    },
                },
            ]),
            minimum: 1usize,
            maximum: 64usize,
            sorted_scalar: false,
            sort_by: &["keyId"],
            unique_by: &["keyId"],
        },
    },
]);
const NATIVE_REPRODUCIBILITY_RECORD_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "payload",
        spec: RSpec::Record(&[
            RFieldSpec {
                name: "schema",
                spec: RSpec::Identifier {
                    values: Some(&["keep.native-repro"]),
                },
            },
            RFieldSpec {
                name: "version",
                spec: RSpec::Uint {
                    minimum: 1u64,
                    maximum: 1u64,
                },
            },
            RFieldSpec {
                name: "comparerIdentityEnvelopeDigest",
                spec: RSpec::Digest("ComparerIdentityEnvelopeDigest"),
            },
            RFieldSpec {
                name: "buildId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "targetTriple",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "variant",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "nativeArtifactInventoryDigest",
                spec: RSpec::Digest("NativeArtifactInventoryDigest"),
            },
            RFieldSpec {
                name: "nativePackagePayloadDigest",
                spec: RSpec::Digest("NativePackagePayloadDigest"),
            },
            RFieldSpec {
                name: "toolchainClosureEnvelopeDigest",
                spec: RSpec::Digest("ToolchainClosureEnvelopeDigest"),
            },
            RFieldSpec {
                name: "builderProvenanceEnvelopeDigests",
                spec: RSpec::Array {
                    item: &RSpec::Digest("ProvenanceEnvelopeDigest"),
                    minimum: 2usize,
                    maximum: 8usize,
                    sorted_scalar: true,
                    sort_by: &[],
                    unique_by: &[],
                },
            },
            RFieldSpec {
                name: "comparisonAlgorithm",
                spec: RSpec::Identifier {
                    values: Some(&["sha256-byte-for-byte/v1"]),
                },
            },
            RFieldSpec {
                name: "comparisonDigest",
                spec: RSpec::Digest("ComparisonDigest"),
            },
            RFieldSpec {
                name: "disagreements",
                spec: RSpec::Array {
                    item: &RSpec::Record(&[
                        RFieldSpec {
                            name: "path",
                            spec: RSpec::Text {
                                values: None,
                                pattern: Some(
                                    "^(?!\\/)(?!.*(?:^|\\/)\\.\\.?(?:\\/|$))(?!.*\\/\\/)[A-Za-z0-9._+-]+(?:\\/[A-Za-z0-9._+-]+)*$",
                                ),
                            },
                        },
                        RFieldSpec {
                            name: "leftBuilderId",
                            spec: RSpec::Identifier { values: None },
                        },
                        RFieldSpec {
                            name: "rightBuilderId",
                            spec: RSpec::Identifier { values: None },
                        },
                        RFieldSpec {
                            name: "leftDigest",
                            spec: RSpec::Digest("ComparedArtifactDigest"),
                        },
                        RFieldSpec {
                            name: "rightDigest",
                            spec: RSpec::Digest("ComparedArtifactDigest"),
                        },
                        RFieldSpec {
                            name: "reasonCode",
                            spec: RSpec::Identifier { values: None },
                        },
                    ]),
                    minimum: 0usize,
                    maximum: 1024usize,
                    sorted_scalar: false,
                    sort_by: &["path", "leftBuilderId", "rightBuilderId"],
                    unique_by: &["path", "leftBuilderId", "rightBuilderId"],
                },
            },
        ]),
    },
    RFieldSpec {
        name: "payloadDigest",
        spec: RSpec::Digest("PayloadDigest"),
    },
    RFieldSpec {
        name: "signatures",
        spec: RSpec::Array {
            item: &RSpec::Record(&[
                RFieldSpec {
                    name: "keyId",
                    spec: RSpec::Identifier { values: None },
                },
                RFieldSpec {
                    name: "algorithm",
                    spec: RSpec::Identifier {
                        values: Some(&["ed25519"]),
                    },
                },
                RFieldSpec {
                    name: "keyEpoch",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "signature",
                    spec: RSpec::Bytes {
                        exact: Some(64usize),
                        maximum: None,
                    },
                },
            ]),
            minimum: 1usize,
            maximum: 64usize,
            sorted_scalar: false,
            sort_by: &["keyId"],
            unique_by: &["keyId"],
        },
    },
]);
const NATIVE_REVOCATION_LOCATOR_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-revocation-locator"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "sequence",
        spec: RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        },
    },
    RFieldSpec {
        name: "revocationEnvelopeDigest",
        spec: RSpec::Digest("RevocationEnvelopeDigest"),
    },
]);
const NATIVE_REVOCATION_RECOVERY_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "payload",
        spec: RSpec::Record(&[
            RFieldSpec {
                name: "schema",
                spec: RSpec::Identifier {
                    values: Some(&["keep.native-revocation-recovery"]),
                },
            },
            RFieldSpec {
                name: "version",
                spec: RSpec::Uint {
                    minimum: 1u64,
                    maximum: 1u64,
                },
            },
            RFieldSpec {
                name: "trustClass",
                spec: RSpec::Identifier {
                    values: Some(&["production", "development"]),
                },
            },
            RFieldSpec {
                name: "recoveryId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "authorityId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "namespace",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "scope",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "expectedB3State",
                spec: RSpec::Record(&[
                    RFieldSpec {
                        name: "scopeKey",
                        spec: RSpec::Record(&[
                            RFieldSpec {
                                name: "authorityId",
                                spec: RSpec::Identifier { values: None },
                            },
                            RFieldSpec {
                                name: "namespace",
                                spec: RSpec::Identifier { values: None },
                            },
                            RFieldSpec {
                                name: "scope",
                                spec: RSpec::Identifier { values: None },
                            },
                            RFieldSpec {
                                name: "genesisRootDigest",
                                spec: RSpec::Digest("GenesisRootEnvelopeDigest"),
                            },
                        ]),
                    },
                    RFieldSpec {
                        name: "generation",
                        spec: RSpec::Uint {
                            minimum: 0u64,
                            maximum: 18446744073709551615u64,
                        },
                    },
                    RFieldSpec {
                        name: "rootEpoch",
                        spec: RSpec::Uint {
                            minimum: 0u64,
                            maximum: 18446744073709551615u64,
                        },
                    },
                    RFieldSpec {
                        name: "rootEnvelopeDigest",
                        spec: RSpec::Digest("RootEnvelopeDigest"),
                    },
                    RFieldSpec {
                        name: "b3ProfileEnvelopeDigest",
                        spec: RSpec::Digest("B3ProfileEnvelopeDigest"),
                    },
                    RFieldSpec {
                        name: "headSequence",
                        spec: RSpec::Uint {
                            minimum: 0u64,
                            maximum: 18446744073709551615u64,
                        },
                    },
                    RFieldSpec {
                        name: "headEnvelopeDigest",
                        spec: RSpec::Digest("RevocationEnvelopeDigest"),
                    },
                    RFieldSpec {
                        name: "deploymentEpoch",
                        spec: RSpec::Uint {
                            minimum: 0u64,
                            maximum: 18446744073709551615u64,
                        },
                    },
                    RFieldSpec {
                        name: "artifactFloor",
                        spec: RSpec::Uint {
                            minimum: 0u64,
                            maximum: 18446744073709551615u64,
                        },
                    },
                    RFieldSpec {
                        name: "counter",
                        spec: RSpec::Uint {
                            minimum: 0u64,
                            maximum: 18446744073709551615u64,
                        },
                    },
                    RFieldSpec {
                        name: "quarantined",
                        spec: RSpec::Boolean,
                    },
                    RFieldSpec {
                        name: "quarantineDigest",
                        spec: RSpec::Digest("QuarantineDigest"),
                    },
                    RFieldSpec {
                        name: "consumedAuthorization",
                        spec: RSpec::Nullable(&RSpec::Tagged {
                            tag: "kind",
                            variants: &[
                                VariantSpec {
                                    name: "rollback",
                                    spec: RSpec::Record(&[
                                        RFieldSpec {
                                            name: "kind",
                                            spec: RSpec::Identifier {
                                                values: Some(&["rollback"]),
                                            },
                                        },
                                        RFieldSpec {
                                            name: "authorizationEnvelopeDigest",
                                            spec: RSpec::Digest(
                                                "RollbackAuthorizationEnvelopeDigest",
                                            ),
                                        },
                                    ]),
                                },
                                VariantSpec {
                                    name: "recovery",
                                    spec: RSpec::Record(&[
                                        RFieldSpec {
                                            name: "kind",
                                            spec: RSpec::Identifier {
                                                values: Some(&["recovery"]),
                                            },
                                        },
                                        RFieldSpec {
                                            name: "authorizationEnvelopeDigest",
                                            spec: RSpec::Digest("RevocationRecoveryEnvelopeDigest"),
                                        },
                                    ]),
                                },
                            ],
                        }),
                    },
                ]),
            },
            RFieldSpec {
                name: "proposedB3StateProjection",
                spec: RSpec::Record(&[
                    RFieldSpec {
                        name: "scopeKey",
                        spec: RSpec::Record(&[
                            RFieldSpec {
                                name: "authorityId",
                                spec: RSpec::Identifier { values: None },
                            },
                            RFieldSpec {
                                name: "namespace",
                                spec: RSpec::Identifier { values: None },
                            },
                            RFieldSpec {
                                name: "scope",
                                spec: RSpec::Identifier { values: None },
                            },
                            RFieldSpec {
                                name: "genesisRootDigest",
                                spec: RSpec::Digest("GenesisRootEnvelopeDigest"),
                            },
                        ]),
                    },
                    RFieldSpec {
                        name: "rootEpoch",
                        spec: RSpec::Uint {
                            minimum: 0u64,
                            maximum: 18446744073709551615u64,
                        },
                    },
                    RFieldSpec {
                        name: "rootEnvelopeDigest",
                        spec: RSpec::Digest("RootEnvelopeDigest"),
                    },
                    RFieldSpec {
                        name: "b3ProfileEnvelopeDigest",
                        spec: RSpec::Digest("B3ProfileEnvelopeDigest"),
                    },
                    RFieldSpec {
                        name: "headSequence",
                        spec: RSpec::Uint {
                            minimum: 0u64,
                            maximum: 18446744073709551615u64,
                        },
                    },
                    RFieldSpec {
                        name: "headEnvelopeDigest",
                        spec: RSpec::Digest("RevocationEnvelopeDigest"),
                    },
                    RFieldSpec {
                        name: "deploymentEpoch",
                        spec: RSpec::Uint {
                            minimum: 0u64,
                            maximum: 18446744073709551615u64,
                        },
                    },
                    RFieldSpec {
                        name: "artifactFloor",
                        spec: RSpec::Uint {
                            minimum: 0u64,
                            maximum: 18446744073709551615u64,
                        },
                    },
                    RFieldSpec {
                        name: "counter",
                        spec: RSpec::Uint {
                            minimum: 0u64,
                            maximum: 18446744073709551615u64,
                        },
                    },
                    RFieldSpec {
                        name: "quarantined",
                        spec: RSpec::Boolean,
                    },
                    RFieldSpec {
                        name: "quarantineDigest",
                        spec: RSpec::Digest("QuarantineDigest"),
                    },
                ]),
            },
            RFieldSpec {
                name: "quarantinedHeadEnvelopeDigests",
                spec: RSpec::Array {
                    item: &RSpec::Digest("RevocationEnvelopeDigest"),
                    minimum: 1usize,
                    maximum: 4096usize,
                    sorted_scalar: true,
                    sort_by: &[],
                    unique_by: &[],
                },
            },
            RFieldSpec {
                name: "selectedHeadEnvelopeDigest",
                spec: RSpec::Digest("RevocationEnvelopeDigest"),
            },
            RFieldSpec {
                name: "selectedSequence",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "issuedCounter",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "expiresCounter",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "reasonCode",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "transcriptDigest",
                spec: RSpec::Digest("TranscriptDigest"),
            },
        ]),
    },
    RFieldSpec {
        name: "payloadDigest",
        spec: RSpec::Digest("PayloadDigest"),
    },
    RFieldSpec {
        name: "signatures",
        spec: RSpec::Array {
            item: &RSpec::Record(&[
                RFieldSpec {
                    name: "keyId",
                    spec: RSpec::Identifier { values: None },
                },
                RFieldSpec {
                    name: "algorithm",
                    spec: RSpec::Identifier {
                        values: Some(&["ed25519"]),
                    },
                },
                RFieldSpec {
                    name: "keyEpoch",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "signature",
                    spec: RSpec::Bytes {
                        exact: Some(64usize),
                        maximum: None,
                    },
                },
            ]),
            minimum: 1usize,
            maximum: 64usize,
            sorted_scalar: false,
            sort_by: &["keyId"],
            unique_by: &["keyId"],
        },
    },
]);
const NATIVE_ROLLBACK_AUTHORIZATION_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "payload",
        spec: RSpec::Record(&[
            RFieldSpec {
                name: "schema",
                spec: RSpec::Identifier {
                    values: Some(&["keep.native-rollback"]),
                },
            },
            RFieldSpec {
                name: "version",
                spec: RSpec::Uint {
                    minimum: 1u64,
                    maximum: 1u64,
                },
            },
            RFieldSpec {
                name: "trustClass",
                spec: RSpec::Identifier {
                    values: Some(&["production", "development"]),
                },
            },
            RFieldSpec {
                name: "authorizationId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "fromDeploymentEnvelopeDigest",
                spec: RSpec::Digest("DeploymentEnvelopeDigest"),
            },
            RFieldSpec {
                name: "fromDeploymentEpoch",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "fromArtifactVersion",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "toDeploymentBaseDigest",
                spec: RSpec::Digest("DeploymentBaseDigest"),
            },
            RFieldSpec {
                name: "toDeploymentEpoch",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "toArtifactVersion",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "minimumArtifactVersion",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "predecessorDigest",
                spec: RSpec::Digest("RollbackAuthorizationEnvelopeDigest"),
            },
            RFieldSpec {
                name: "issuedCounter",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "expiresCounter",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "nonce",
                spec: RSpec::Bytes {
                    exact: Some(32usize),
                    maximum: None,
                },
            },
        ]),
    },
    RFieldSpec {
        name: "payloadDigest",
        spec: RSpec::Digest("PayloadDigest"),
    },
    RFieldSpec {
        name: "signatures",
        spec: RSpec::Array {
            item: &RSpec::Record(&[
                RFieldSpec {
                    name: "keyId",
                    spec: RSpec::Identifier { values: None },
                },
                RFieldSpec {
                    name: "algorithm",
                    spec: RSpec::Identifier {
                        values: Some(&["ed25519"]),
                    },
                },
                RFieldSpec {
                    name: "keyEpoch",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "signature",
                    spec: RSpec::Bytes {
                        exact: Some(64usize),
                        maximum: None,
                    },
                },
            ]),
            minimum: 1usize,
            maximum: 64usize,
            sorted_scalar: false,
            sort_by: &["keyId"],
            unique_by: &["keyId"],
        },
    },
]);
const NATIVE_ROOT_CEREMONY_RECORD_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "payload",
        spec: RSpec::Record(&[
            RFieldSpec {
                name: "schema",
                spec: RSpec::Identifier {
                    values: Some(&["keep.native-root-ceremony"]),
                },
            },
            RFieldSpec {
                name: "version",
                spec: RSpec::Uint {
                    minimum: 1u64,
                    maximum: 1u64,
                },
            },
            RFieldSpec {
                name: "trustClass",
                spec: RSpec::Identifier {
                    values: Some(&["production", "development"]),
                },
            },
            RFieldSpec {
                name: "ceremonyId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "rootEnvelopeDigest",
                spec: RSpec::Digest("RootEnvelopeDigest"),
            },
            RFieldSpec {
                name: "genesisCarrierDigest",
                spec: RSpec::Digest("GenesisCarrierDigest"),
            },
            RFieldSpec {
                name: "participantKeyIds",
                spec: RSpec::Array {
                    item: &RSpec::Identifier { values: None },
                    minimum: 1usize,
                    maximum: 64usize,
                    sorted_scalar: true,
                    sort_by: &[],
                    unique_by: &[],
                },
            },
            RFieldSpec {
                name: "requestDigest",
                spec: RSpec::Digest("CeremonyRequestDigest"),
            },
            RFieldSpec {
                name: "transcriptDigest",
                spec: RSpec::Digest("TranscriptDigest"),
            },
            RFieldSpec {
                name: "issuedCounter",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
        ]),
    },
    RFieldSpec {
        name: "payloadDigest",
        spec: RSpec::Digest("PayloadDigest"),
    },
    RFieldSpec {
        name: "signatures",
        spec: RSpec::Array {
            item: &RSpec::Record(&[
                RFieldSpec {
                    name: "keyId",
                    spec: RSpec::Identifier { values: None },
                },
                RFieldSpec {
                    name: "algorithm",
                    spec: RSpec::Identifier {
                        values: Some(&["ed25519"]),
                    },
                },
                RFieldSpec {
                    name: "keyEpoch",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "signature",
                    spec: RSpec::Bytes {
                        exact: Some(64usize),
                        maximum: None,
                    },
                },
            ]),
            minimum: 1usize,
            maximum: 64usize,
            sorted_scalar: false,
            sort_by: &["keyId"],
            unique_by: &["keyId"],
        },
    },
]);
const NATIVE_ROOT_LOCATOR_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-root-locator"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "rootEpoch",
        spec: RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        },
    },
    RFieldSpec {
        name: "rootEnvelopeDigest",
        spec: RSpec::Digest("RootEnvelopeDigest"),
    },
]);
const NATIVE_ROOT_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "payload",
        spec: RSpec::Record(&[
            RFieldSpec {
                name: "schema",
                spec: RSpec::Identifier {
                    values: Some(&["keep.native-root"]),
                },
            },
            RFieldSpec {
                name: "version",
                spec: RSpec::Uint {
                    minimum: 1u64,
                    maximum: 1u64,
                },
            },
            RFieldSpec {
                name: "trustClass",
                spec: RSpec::Identifier {
                    values: Some(&["production", "development"]),
                },
            },
            RFieldSpec {
                name: "rootId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "rootEpoch",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "genesisEpochDigest",
                spec: RSpec::Digest("GenesisEpochDigest"),
            },
            RFieldSpec {
                name: "predecessorRootEnvelopeDigest",
                spec: RSpec::Nullable(&RSpec::Digest("RootEnvelopeDigest")),
            },
            RFieldSpec {
                name: "issuedCounter",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "threshold",
                spec: RSpec::Record(&[
                    RFieldSpec {
                        name: "root",
                        spec: RSpec::Uint {
                            minimum: 1u64,
                            maximum: 32u64,
                        },
                    },
                    RFieldSpec {
                        name: "release",
                        spec: RSpec::Uint {
                            minimum: 1u64,
                            maximum: 32u64,
                        },
                    },
                    RFieldSpec {
                        name: "timestamp",
                        spec: RSpec::Uint {
                            minimum: 1u64,
                            maximum: 32u64,
                        },
                    },
                    RFieldSpec {
                        name: "revocation",
                        spec: RSpec::Uint {
                            minimum: 1u64,
                            maximum: 32u64,
                        },
                    },
                    RFieldSpec {
                        name: "recovery",
                        spec: RSpec::Uint {
                            minimum: 1u64,
                            maximum: 32u64,
                        },
                    },
                    RFieldSpec {
                        name: "b3",
                        spec: RSpec::Uint {
                            minimum: 1u64,
                            maximum: 32u64,
                        },
                    },
                    RFieldSpec {
                        name: "builder",
                        spec: RSpec::Uint {
                            minimum: 1u64,
                            maximum: 32u64,
                        },
                    },
                    RFieldSpec {
                        name: "comparer",
                        spec: RSpec::Uint {
                            minimum: 1u64,
                            maximum: 32u64,
                        },
                    },
                ]),
            },
            RFieldSpec {
                name: "rootKeys",
                spec: RSpec::Array {
                    item: &RSpec::Record(&[
                        RFieldSpec {
                            name: "keyId",
                            spec: RSpec::Identifier { values: None },
                        },
                        RFieldSpec {
                            name: "algorithm",
                            spec: RSpec::Identifier {
                                values: Some(&["ed25519"]),
                            },
                        },
                        RFieldSpec {
                            name: "publicKey",
                            spec: RSpec::Bytes {
                                exact: Some(32usize),
                                maximum: None,
                            },
                        },
                        RFieldSpec {
                            name: "keyEpoch",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                        RFieldSpec {
                            name: "validFromCounter",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                        RFieldSpec {
                            name: "validUntilCounter",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                    ]),
                    minimum: 1usize,
                    maximum: 32usize,
                    sorted_scalar: false,
                    sort_by: &["keyId"],
                    unique_by: &["keyId"],
                },
            },
            RFieldSpec {
                name: "releaseKeys",
                spec: RSpec::Array {
                    item: &RSpec::Record(&[
                        RFieldSpec {
                            name: "keyId",
                            spec: RSpec::Identifier { values: None },
                        },
                        RFieldSpec {
                            name: "algorithm",
                            spec: RSpec::Identifier {
                                values: Some(&["ed25519"]),
                            },
                        },
                        RFieldSpec {
                            name: "publicKey",
                            spec: RSpec::Bytes {
                                exact: Some(32usize),
                                maximum: None,
                            },
                        },
                        RFieldSpec {
                            name: "keyEpoch",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                        RFieldSpec {
                            name: "validFromCounter",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                        RFieldSpec {
                            name: "validUntilCounter",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                    ]),
                    minimum: 1usize,
                    maximum: 32usize,
                    sorted_scalar: false,
                    sort_by: &["keyId"],
                    unique_by: &["keyId"],
                },
            },
            RFieldSpec {
                name: "timestampKeys",
                spec: RSpec::Array {
                    item: &RSpec::Record(&[
                        RFieldSpec {
                            name: "keyId",
                            spec: RSpec::Identifier { values: None },
                        },
                        RFieldSpec {
                            name: "algorithm",
                            spec: RSpec::Identifier {
                                values: Some(&["ed25519"]),
                            },
                        },
                        RFieldSpec {
                            name: "publicKey",
                            spec: RSpec::Bytes {
                                exact: Some(32usize),
                                maximum: None,
                            },
                        },
                        RFieldSpec {
                            name: "keyEpoch",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                        RFieldSpec {
                            name: "validFromCounter",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                        RFieldSpec {
                            name: "validUntilCounter",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                    ]),
                    minimum: 1usize,
                    maximum: 32usize,
                    sorted_scalar: false,
                    sort_by: &["keyId"],
                    unique_by: &["keyId"],
                },
            },
            RFieldSpec {
                name: "revocationKeys",
                spec: RSpec::Array {
                    item: &RSpec::Record(&[
                        RFieldSpec {
                            name: "keyId",
                            spec: RSpec::Identifier { values: None },
                        },
                        RFieldSpec {
                            name: "algorithm",
                            spec: RSpec::Identifier {
                                values: Some(&["ed25519"]),
                            },
                        },
                        RFieldSpec {
                            name: "publicKey",
                            spec: RSpec::Bytes {
                                exact: Some(32usize),
                                maximum: None,
                            },
                        },
                        RFieldSpec {
                            name: "keyEpoch",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                        RFieldSpec {
                            name: "validFromCounter",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                        RFieldSpec {
                            name: "validUntilCounter",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                    ]),
                    minimum: 1usize,
                    maximum: 32usize,
                    sorted_scalar: false,
                    sort_by: &["keyId"],
                    unique_by: &["keyId"],
                },
            },
            RFieldSpec {
                name: "recoveryKeys",
                spec: RSpec::Array {
                    item: &RSpec::Record(&[
                        RFieldSpec {
                            name: "keyId",
                            spec: RSpec::Identifier { values: None },
                        },
                        RFieldSpec {
                            name: "algorithm",
                            spec: RSpec::Identifier {
                                values: Some(&["ed25519"]),
                            },
                        },
                        RFieldSpec {
                            name: "publicKey",
                            spec: RSpec::Bytes {
                                exact: Some(32usize),
                                maximum: None,
                            },
                        },
                        RFieldSpec {
                            name: "keyEpoch",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                        RFieldSpec {
                            name: "validFromCounter",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                        RFieldSpec {
                            name: "validUntilCounter",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                    ]),
                    minimum: 1usize,
                    maximum: 32usize,
                    sorted_scalar: false,
                    sort_by: &["keyId"],
                    unique_by: &["keyId"],
                },
            },
            RFieldSpec {
                name: "b3Keys",
                spec: RSpec::Array {
                    item: &RSpec::Record(&[
                        RFieldSpec {
                            name: "keyId",
                            spec: RSpec::Identifier { values: None },
                        },
                        RFieldSpec {
                            name: "algorithm",
                            spec: RSpec::Identifier {
                                values: Some(&["ed25519"]),
                            },
                        },
                        RFieldSpec {
                            name: "publicKey",
                            spec: RSpec::Bytes {
                                exact: Some(32usize),
                                maximum: None,
                            },
                        },
                        RFieldSpec {
                            name: "keyEpoch",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                        RFieldSpec {
                            name: "validFromCounter",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                        RFieldSpec {
                            name: "validUntilCounter",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                    ]),
                    minimum: 1usize,
                    maximum: 32usize,
                    sorted_scalar: false,
                    sort_by: &["keyId"],
                    unique_by: &["keyId"],
                },
            },
            RFieldSpec {
                name: "builderKeys",
                spec: RSpec::Array {
                    item: &RSpec::Record(&[
                        RFieldSpec {
                            name: "keyId",
                            spec: RSpec::Identifier { values: None },
                        },
                        RFieldSpec {
                            name: "algorithm",
                            spec: RSpec::Identifier {
                                values: Some(&["ed25519"]),
                            },
                        },
                        RFieldSpec {
                            name: "publicKey",
                            spec: RSpec::Bytes {
                                exact: Some(32usize),
                                maximum: None,
                            },
                        },
                        RFieldSpec {
                            name: "keyEpoch",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                        RFieldSpec {
                            name: "validFromCounter",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                        RFieldSpec {
                            name: "validUntilCounter",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                    ]),
                    minimum: 1usize,
                    maximum: 32usize,
                    sorted_scalar: false,
                    sort_by: &["keyId"],
                    unique_by: &["keyId"],
                },
            },
            RFieldSpec {
                name: "comparerKeys",
                spec: RSpec::Array {
                    item: &RSpec::Record(&[
                        RFieldSpec {
                            name: "keyId",
                            spec: RSpec::Identifier { values: None },
                        },
                        RFieldSpec {
                            name: "algorithm",
                            spec: RSpec::Identifier {
                                values: Some(&["ed25519"]),
                            },
                        },
                        RFieldSpec {
                            name: "publicKey",
                            spec: RSpec::Bytes {
                                exact: Some(32usize),
                                maximum: None,
                            },
                        },
                        RFieldSpec {
                            name: "keyEpoch",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                        RFieldSpec {
                            name: "validFromCounter",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                        RFieldSpec {
                            name: "validUntilCounter",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                    ]),
                    minimum: 1usize,
                    maximum: 32usize,
                    sorted_scalar: false,
                    sort_by: &["keyId"],
                    unique_by: &["keyId"],
                },
            },
            RFieldSpec {
                name: "keyEpochs",
                spec: RSpec::Array {
                    item: &RSpec::Record(&[
                        RFieldSpec {
                            name: "role",
                            spec: RSpec::Identifier {
                                values: Some(&[
                                    "root",
                                    "release",
                                    "timestamp",
                                    "revocation",
                                    "recovery",
                                    "b3",
                                    "builder",
                                    "comparer",
                                ]),
                            },
                        },
                        RFieldSpec {
                            name: "minimumEpoch",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                    ]),
                    minimum: 8usize,
                    maximum: 8usize,
                    sorted_scalar: false,
                    sort_by: &["role"],
                    unique_by: &["role"],
                },
            },
        ]),
    },
    RFieldSpec {
        name: "payloadDigest",
        spec: RSpec::Digest("PayloadDigest"),
    },
    RFieldSpec {
        name: "signatures",
        spec: RSpec::Array {
            item: &RSpec::OneOf(&[
                RSpec::Record(&[
                    RFieldSpec {
                        name: "keyId",
                        spec: RSpec::Identifier { values: None },
                    },
                    RFieldSpec {
                        name: "algorithm",
                        spec: RSpec::Identifier {
                            values: Some(&["ed25519"]),
                        },
                    },
                    RFieldSpec {
                        name: "keyEpoch",
                        spec: RSpec::Uint {
                            minimum: 0u64,
                            maximum: 18446744073709551615u64,
                        },
                    },
                    RFieldSpec {
                        name: "signature",
                        spec: RSpec::Bytes {
                            exact: Some(64usize),
                            maximum: None,
                        },
                    },
                ]),
                RSpec::Record(&[
                    RFieldSpec {
                        name: "keyId",
                        spec: RSpec::Identifier { values: None },
                    },
                    RFieldSpec {
                        name: "algorithm",
                        spec: RSpec::Identifier {
                            values: Some(&["ed25519"]),
                        },
                    },
                    RFieldSpec {
                        name: "keyEpoch",
                        spec: RSpec::Uint {
                            minimum: 0u64,
                            maximum: 18446744073709551615u64,
                        },
                    },
                    RFieldSpec {
                        name: "authorizationRole",
                        spec: RSpec::Identifier {
                            values: Some(&["root", "recovery"]),
                        },
                    },
                    RFieldSpec {
                        name: "signature",
                        spec: RSpec::Bytes {
                            exact: Some(64usize),
                            maximum: None,
                        },
                    },
                ]),
            ]),
            minimum: 1usize,
            maximum: 64usize,
            sorted_scalar: false,
            sort_by: &["keyId"],
            unique_by: &["keyId"],
        },
    },
]);
const NATIVE_SBOM_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "payload",
        spec: RSpec::Record(&[
            RFieldSpec {
                name: "schema",
                spec: RSpec::Identifier {
                    values: Some(&["keep.native-sbom"]),
                },
            },
            RFieldSpec {
                name: "version",
                spec: RSpec::Uint {
                    minimum: 1u64,
                    maximum: 1u64,
                },
            },
            RFieldSpec {
                name: "buildId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "targetTriple",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "variant",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "nativeArtifactInventoryDigest",
                spec: RSpec::Digest("NativeArtifactInventoryDigest"),
            },
            RFieldSpec {
                name: "packages",
                spec: RSpec::Array {
                    item: &RSpec::Record(&[
                        RFieldSpec {
                            name: "purl",
                            spec: RSpec::Text {
                                values: None,
                                pattern: None,
                            },
                        },
                        RFieldSpec {
                            name: "name",
                            spec: RSpec::Identifier { values: None },
                        },
                        RFieldSpec {
                            name: "version",
                            spec: RSpec::Text {
                                values: None,
                                pattern: None,
                            },
                        },
                        RFieldSpec {
                            name: "license",
                            spec: RSpec::Text {
                                values: None,
                                pattern: None,
                            },
                        },
                        RFieldSpec {
                            name: "sourceDigest",
                            spec: RSpec::Digest("SourceDigest"),
                        },
                        RFieldSpec {
                            name: "checksumAlgorithm",
                            spec: RSpec::Identifier {
                                values: Some(&["sha256"]),
                            },
                        },
                        RFieldSpec {
                            name: "checksum",
                            spec: RSpec::Digest("SbomChecksumDigest"),
                        },
                    ]),
                    minimum: 0usize,
                    maximum: 4096usize,
                    sorted_scalar: false,
                    sort_by: &["purl"],
                    unique_by: &["purl"],
                },
            },
        ]),
    },
    RFieldSpec {
        name: "payloadDigest",
        spec: RSpec::Digest("PayloadDigest"),
    },
    RFieldSpec {
        name: "signatures",
        spec: RSpec::Array {
            item: &RSpec::Record(&[
                RFieldSpec {
                    name: "keyId",
                    spec: RSpec::Identifier { values: None },
                },
                RFieldSpec {
                    name: "algorithm",
                    spec: RSpec::Identifier {
                        values: Some(&["ed25519"]),
                    },
                },
                RFieldSpec {
                    name: "keyEpoch",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "signature",
                    spec: RSpec::Bytes {
                        exact: Some(64usize),
                        maximum: None,
                    },
                },
            ]),
            minimum: 1usize,
            maximum: 64usize,
            sorted_scalar: false,
            sort_by: &["keyId"],
            unique_by: &["keyId"],
        },
    },
]);
const NATIVE_SECCOMP_POLICY_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-seccomp-policy"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "architecture",
        spec: RSpec::Identifier {
            values: Some(&["x86_64", "aarch64"]),
        },
    },
    RFieldSpec {
        name: "defaultAction",
        spec: RSpec::Identifier {
            values: Some(&["kill-process"]),
        },
    },
    RFieldSpec {
        name: "rules",
        spec: RSpec::Array {
            item: &RSpec::Record(&[
                RFieldSpec {
                    name: "syscall",
                    spec: RSpec::Identifier { values: None },
                },
                RFieldSpec {
                    name: "action",
                    spec: RSpec::Identifier {
                        values: Some(&["allow", "kill-process", "errno"]),
                    },
                },
                RFieldSpec {
                    name: "errno",
                    spec: RSpec::Nullable(&RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    }),
                },
                RFieldSpec {
                    name: "arguments",
                    spec: RSpec::Array {
                        item: &RSpec::Record(&[
                            RFieldSpec {
                                name: "index",
                                spec: RSpec::Uint {
                                    minimum: 0u64,
                                    maximum: 5u64,
                                },
                            },
                            RFieldSpec {
                                name: "operator",
                                spec: RSpec::Identifier {
                                    values: Some(&[
                                        "eq",
                                        "ne",
                                        "lt",
                                        "le",
                                        "gt",
                                        "ge",
                                        "masked-eq",
                                    ]),
                                },
                            },
                            RFieldSpec {
                                name: "value",
                                spec: RSpec::Uint {
                                    minimum: 0u64,
                                    maximum: 18446744073709551615u64,
                                },
                            },
                            RFieldSpec {
                                name: "mask",
                                spec: RSpec::Nullable(&RSpec::Uint {
                                    minimum: 0u64,
                                    maximum: 18446744073709551615u64,
                                }),
                            },
                        ]),
                        minimum: 0usize,
                        maximum: 6usize,
                        sorted_scalar: false,
                        sort_by: &["index"],
                        unique_by: &["index"],
                    },
                },
            ]),
            minimum: 0usize,
            maximum: 512usize,
            sorted_scalar: false,
            sort_by: &["syscall"],
            unique_by: &["syscall"],
        },
    },
]);
const NATIVE_TIMESTAMP_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "payload",
        spec: RSpec::Record(&[
            RFieldSpec {
                name: "schema",
                spec: RSpec::Identifier {
                    values: Some(&["keep.native-timestamp"]),
                },
            },
            RFieldSpec {
                name: "version",
                spec: RSpec::Uint {
                    minimum: 1u64,
                    maximum: 1u64,
                },
            },
            RFieldSpec {
                name: "trustClass",
                spec: RSpec::Identifier {
                    values: Some(&["production", "development"]),
                },
            },
            RFieldSpec {
                name: "nativeClosureBaseDigest",
                spec: RSpec::Digest("ReleaseClosureBaseDigest"),
            },
            RFieldSpec {
                name: "artifactVersion",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "deploymentEpoch",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "releaseKeyEpoch",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "timestampKeyEpoch",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "issuedCounter",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "expiresCounter",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
            RFieldSpec {
                name: "revocationCheckpointEnvelopeDigest",
                spec: RSpec::Digest("RevocationEnvelopeDigest"),
            },
            RFieldSpec {
                name: "revocationSequence",
                spec: RSpec::Uint {
                    minimum: 0u64,
                    maximum: 18446744073709551615u64,
                },
            },
        ]),
    },
    RFieldSpec {
        name: "payloadDigest",
        spec: RSpec::Digest("PayloadDigest"),
    },
    RFieldSpec {
        name: "signatures",
        spec: RSpec::Array {
            item: &RSpec::Record(&[
                RFieldSpec {
                    name: "keyId",
                    spec: RSpec::Identifier { values: None },
                },
                RFieldSpec {
                    name: "algorithm",
                    spec: RSpec::Identifier {
                        values: Some(&["ed25519"]),
                    },
                },
                RFieldSpec {
                    name: "keyEpoch",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "signature",
                    spec: RSpec::Bytes {
                        exact: Some(64usize),
                        maximum: None,
                    },
                },
            ]),
            minimum: 1usize,
            maximum: 64usize,
            sorted_scalar: false,
            sort_by: &["keyId"],
            unique_by: &["keyId"],
        },
    },
]);
const NATIVE_TOOLCHAIN_CLOSURE_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "payload",
        spec: RSpec::Record(&[
            RFieldSpec {
                name: "schema",
                spec: RSpec::Identifier {
                    values: Some(&["keep.native-toolchain"]),
                },
            },
            RFieldSpec {
                name: "version",
                spec: RSpec::Uint {
                    minimum: 1u64,
                    maximum: 1u64,
                },
            },
            RFieldSpec {
                name: "toolchainId",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "targetTriple",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "variant",
                spec: RSpec::Identifier { values: None },
            },
            RFieldSpec {
                name: "compilerDigest",
                spec: RSpec::Digest("CompilerDigest"),
            },
            RFieldSpec {
                name: "sysrootDigest",
                spec: RSpec::Digest("SysrootDigest"),
            },
            RFieldSpec {
                name: "linkerDigest",
                spec: RSpec::Digest("LinkerDigest"),
            },
            RFieldSpec {
                name: "vendorDigest",
                spec: RSpec::Digest("VendorDigest"),
            },
            RFieldSpec {
                name: "containerDigest",
                spec: RSpec::Digest("ContainerDigest"),
            },
            RFieldSpec {
                name: "environmentPolicyDigest",
                spec: RSpec::Digest("EnvironmentPolicyDigest"),
            },
            RFieldSpec {
                name: "entries",
                spec: RSpec::Array {
                    item: &RSpec::Record(&[
                        RFieldSpec {
                            name: "path",
                            spec: RSpec::Text {
                                values: None,
                                pattern: Some(
                                    "^(?!\\/)(?!.*(?:^|\\/)\\.\\.?(?:\\/|$))(?!.*\\/\\/)[A-Za-z0-9._+-]+(?:\\/[A-Za-z0-9._+-]+)*$",
                                ),
                            },
                        },
                        RFieldSpec {
                            name: "size",
                            spec: RSpec::Uint {
                                minimum: 0u64,
                                maximum: 18446744073709551615u64,
                            },
                        },
                        RFieldSpec {
                            name: "digest",
                            spec: RSpec::Digest("ToolchainEntryDigest"),
                        },
                        RFieldSpec {
                            name: "kind",
                            spec: RSpec::Identifier {
                                values: Some(&[
                                    "compiler",
                                    "rustlib",
                                    "linker",
                                    "sysroot",
                                    "vendor-source",
                                    "container-manifest",
                                    "build-tool",
                                ]),
                            },
                        },
                    ]),
                    minimum: 0usize,
                    maximum: 8192usize,
                    sorted_scalar: false,
                    sort_by: &["path"],
                    unique_by: &["path"],
                },
            },
        ]),
    },
    RFieldSpec {
        name: "payloadDigest",
        spec: RSpec::Digest("PayloadDigest"),
    },
    RFieldSpec {
        name: "signatures",
        spec: RSpec::Array {
            item: &RSpec::Record(&[
                RFieldSpec {
                    name: "keyId",
                    spec: RSpec::Identifier { values: None },
                },
                RFieldSpec {
                    name: "algorithm",
                    spec: RSpec::Identifier {
                        values: Some(&["ed25519"]),
                    },
                },
                RFieldSpec {
                    name: "keyEpoch",
                    spec: RSpec::Uint {
                        minimum: 0u64,
                        maximum: 18446744073709551615u64,
                    },
                },
                RFieldSpec {
                    name: "signature",
                    spec: RSpec::Bytes {
                        exact: Some(64usize),
                        maximum: None,
                    },
                },
            ]),
            minimum: 1usize,
            maximum: 64usize,
            sorted_scalar: false,
            sort_by: &["keyId"],
            unique_by: &["keyId"],
        },
    },
]);
const NATIVE_TRANSCRIPT_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-transcript"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "subjectDigest",
        spec: RSpec::Digest("SubjectDigest"),
    },
    RFieldSpec {
        name: "mechanism",
        spec: RSpec::Identifier { values: None },
    },
    RFieldSpec {
        name: "mechanismVersion",
        spec: RSpec::Identifier { values: None },
    },
    RFieldSpec {
        name: "capturedCounter",
        spec: RSpec::Uint {
            minimum: 0u64,
            maximum: 18446744073709551615u64,
        },
    },
    RFieldSpec {
        name: "resultDigest",
        spec: RSpec::Digest("ObservationResultDigest"),
    },
]);
const NATIVE_TRANSPORT_IDENTITY_V1_SPEC: RSpec = RSpec::Record(&[
    RFieldSpec {
        name: "schema",
        spec: RSpec::Identifier {
            values: Some(&["keep.native-transport-identity"]),
        },
    },
    RFieldSpec {
        name: "version",
        spec: RSpec::Uint {
            minimum: 1u64,
            maximum: 1u64,
        },
    },
    RFieldSpec {
        name: "transportKind",
        spec: RSpec::Identifier {
            values: Some(&["unix-seqpacket", "vsock"]),
        },
    },
    RFieldSpec {
        name: "endpointIdentity",
        spec: RSpec::Text {
            values: None,
            pattern: Some("^[A-Za-z0-9][A-Za-z0-9._+@-]{0,4095}$"),
        },
    },
    RFieldSpec {
        name: "peerPolicyDigest",
        spec: RSpec::Digest("PeerPolicyDigest"),
    },
]);
// Included by p2_schema.rs, whose module declares #![forbid(unsafe_code)].
