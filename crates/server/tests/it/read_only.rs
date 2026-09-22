//! Current-v1 Directory capability regression: only public Realm reads are claimed.

use arkret_wire::{BindingKind, ServiceOperationId, operation_bundle_descriptor};

#[test]
fn public_read_bundle_is_exactly_the_routed_directory_surface() {
    let bundle =
        operation_bundle_descriptor("ak.operation_bundle.directory_service.public_read.v1")
            .expect("generated public_read bundle");
    for operation in [
        ServiceOperationId::FindDirectoryReadDescribeV1,
        ServiceOperationId::FindDirectoryReadSearchRealmsV1,
        ServiceOperationId::FindDirectoryReadResolveRealmV1,
    ] {
        assert!(bundle.contains(operation, BindingKind::HttpJson));
    }
    assert_eq!(bundle.members.len(), 3);

    let doc = server::routing::openapi(&salvo::Router::new());
    assert!(
        doc.pointer("/paths/~1_arkret~1find~1directory~1search-realms/post")
            .is_some()
    );
    assert!(
        doc.pointer("/paths/~1_arkret~1find~1directory~1resolve-realm/post")
            .is_some()
    );
    assert!(
        doc.pointer("/paths/~1_arkret~1find~1directory~1announce")
            .is_none()
    );
    assert!(
        doc.pointer("/paths/~1_arkret~1find~1directory~1withdraw")
            .is_none()
    );
}
