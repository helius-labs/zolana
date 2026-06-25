use std::collections::HashSet;

use anyhow::{bail, Context as AnyhowContext, Result};

use crate::api::api::{OpenApiSpec, PhotonApi};
use crate::api::method::rings::{
    EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse, GetMerkleProofsRequest,
    GetMerkleProofsResponse, GetNonInclusionProofsRequest, GetNonInclusionProofsResponse,
    GetRingsByTagsRequest, GetShieldedTransactionsByTagsResponse, MerkleContext, MerkleProof,
    NonInclusionProof, RingsOutputContext, RingsOutputSlot, ShieldedTransaction,
};
use crate::common::typedefs::bs64_string::Base64String;
use crate::common::typedefs::context::Context;
use crate::common::typedefs::hash::Hash;
use crate::common::typedefs::limit::Limit;
use crate::common::typedefs::serializable_pubkey::SerializablePubkey;
use crate::common::typedefs::serializable_signature::SerializableSignature;
use utoipa::openapi::Components;
use utoipa::openapi::Response;

use crate::common::relative_project_path;

use utoipa::openapi::path::OperationBuilder;

use utoipa::openapi::request_body::RequestBodyBuilder;

use utoipa::openapi::ContentBuilder;

use utoipa::openapi::path::HttpMethod;
use utoipa::openapi::PathItem;

use utoipa::openapi::schema::{ArrayItems, ObjectBuilder, Schema, SchemaType, Type};
use utoipa::openapi::RefOr;
use utoipa::openapi::Required;
use utoipa::openapi::ResponseBuilder;
use utoipa::openapi::ResponsesBuilder;

use utoipa::openapi::ServerBuilder;
use utoipa::OpenApi;

const JSON_CONTENT_TYPE: &str = "application/json";
const RINGS_API_SPEC_FILE: &str = "rings.yaml";
const RINGS_API_TEST_SPEC_FILE: &str = "rings.test.yaml";

#[derive(OpenApi)]
#[openapi(components(schemas(
    SerializablePubkey,
    Context,
    Hash,
    Limit,
    Base64String,
    SerializableSignature,
    GetRingsByTagsRequest,
    EncryptedUtxoMatch,
    GetEncryptedUtxosByTagsResponse,
    RingsOutputContext,
    RingsOutputSlot,
    ShieldedTransaction,
    GetShieldedTransactionsByTagsResponse,
    GetMerkleProofsRequest,
    GetMerkleProofsResponse,
    MerkleContext,
    MerkleProof,
    GetNonInclusionProofsRequest,
    GetNonInclusionProofsResponse,
    NonInclusionProof,
)))]
struct ApiDoc;

fn add_string_property(
    builder: ObjectBuilder,
    name: &str,
    value: &str,
    description: &str,
) -> ObjectBuilder {
    let string_object = ObjectBuilder::new()
        .schema_type(Type::String)
        .description(Some(description.to_string()))
        .enum_values(Some(vec![value.to_string()]))
        .build();

    let string_schema = RefOr::T(Schema::Object(string_object));
    builder.property(name, string_schema)
}

fn build_error_response(description: &str) -> Response {
    let error_object = ObjectBuilder::new()
        .property(
            "code",
            RefOr::T(Schema::Object(
                ObjectBuilder::new().schema_type(Type::Integer).build(),
            )),
        )
        .property(
            "message",
            RefOr::T(Schema::Object(
                ObjectBuilder::new().schema_type(Type::String).build(),
            )),
        )
        .build();

    let response_schema = ObjectBuilder::new()
        .property(
            "jsonrpc",
            RefOr::T(Schema::Object(
                ObjectBuilder::new().schema_type(Type::String).build(),
            )),
        )
        .property(
            "id",
            RefOr::T(Schema::Object(
                ObjectBuilder::new().schema_type(Type::String).build(),
            )),
        )
        .property("error", RefOr::T(Schema::Object(error_object)))
        .build();

    ResponseBuilder::new()
        .description(description)
        .content(
            JSON_CONTENT_TYPE,
            ContentBuilder::new()
                .schema(Some(Schema::Object(response_schema)))
                .build(),
        )
        .build()
}

fn request_schema(name: &str, params: Option<RefOr<Schema>>) -> RefOr<Schema> {
    let mut builder = ObjectBuilder::new();

    builder = add_string_property(
        builder,
        "jsonrpc",
        "2.0",
        "The version of the JSON-RPC protocol.",
    );
    builder = add_string_property(
        builder,
        "id",
        "test-account",
        "An ID to identify the request.",
    );
    builder = add_string_property(builder, "method", name, "The name of the method to invoke.");
    builder = builder
        .required("jsonrpc")
        .required("id")
        .required("method");

    if let Some(params) = params {
        builder = builder.property("params", params);
        builder = builder.required("params");
    }

    RefOr::T(Schema::Object(builder.build()))
}

fn response_schema(result: RefOr<Schema>) -> RefOr<Schema> {
    let mut builder = ObjectBuilder::new();

    builder = add_string_property(
        builder,
        "jsonrpc",
        "2.0",
        "The version of the JSON-RPC protocol.",
    );
    builder = add_string_property(
        builder,
        "id",
        "test-account",
        "An ID to identify the response.",
    );
    builder = builder.property("result", result);

    // Add optional error property
    let error_object = ObjectBuilder::new()
        .property(
            "code",
            RefOr::T(Schema::Object(
                ObjectBuilder::new().schema_type(Type::Integer).build(),
            )),
        )
        .property(
            "message",
            RefOr::T(Schema::Object(
                ObjectBuilder::new().schema_type(Type::String).build(),
            )),
        )
        .build();
    builder = builder.property("error", RefOr::T(Schema::Object(error_object)));

    builder = builder.required("jsonrpc").required("id");

    RefOr::T(Schema::Object(builder.build()))
}

// Examples of allOf references are always {}, which is incorrect.
fn fix_examples_for_all_of_references(schema: RefOr<Schema>) -> RefOr<Schema> {
    match schema {
        RefOr::T(mut schema) => match schema {
            Schema::Object(ref mut object) => RefOr::T(match object.schema_type {
                SchemaType::Type(Type::Object) => {
                    object.properties = object
                        .properties
                        .iter()
                        .map(|(key, value)| {
                            let new_value = fix_examples_for_all_of_references(value.clone());
                            (key.clone(), new_value)
                        })
                        .collect();
                    schema
                }
                _ => schema,
            }),
            Schema::AllOf(ref all_of) if all_of.items.len() == 1 => all_of.items[0].clone(),
            Schema::AllOf(_) => RefOr::T(schema),
            _ => RefOr::T(schema),
        },
        RefOr::Ref(_) => schema,
    }
}

fn find_all_components(schema: RefOr<Schema>) -> HashSet<String> {
    let mut components = HashSet::new();

    match schema {
        RefOr::T(schema) => match schema {
            Schema::Object(object) => {
                for (_, value) in object.properties {
                    components.extend(find_all_components(value));
                }
            }
            Schema::Array(array) => {
                if let ArrayItems::RefOrSchema(items) = array.items {
                    components.extend(find_all_components(*items));
                }
            }
            Schema::AllOf(all_of) => {
                for item in all_of.items {
                    components.extend(find_all_components(item));
                }
            }
            Schema::OneOf(one_of) => {
                for item in one_of.items {
                    components.extend(find_all_components(item));
                }
            }
            Schema::AnyOf(any_of) => {
                for item in any_of.items {
                    components.extend(find_all_components(item));
                }
            }
            _ => {}
        },
        RefOr::Ref(ref_location) => {
            if let Some(component) = ref_location.ref_location.rsplit('/').next() {
                components.insert(component.to_string());
            }
        }
    }

    components
}

fn filter_unused_components_for_specs(
    specs: &[OpenApiSpec],
    components: &mut Components,
) -> Result<()> {
    let mut used_components = HashSet::new();
    for spec in specs {
        if let Some(request) = spec.request.clone() {
            used_components.extend(find_all_components(request));
        }
        used_components.extend(find_all_components(spec.response.clone()));
    }

    let mut check_stack = used_components.clone();
    while let Some(current) = check_stack.iter().next().cloned() {
        check_stack.remove(&current);
        let schema = components
            .schemas
            .get(&current)
            .with_context(|| format!("OpenAPI component '{}' is referenced but missing", current))?
            .clone();
        let child_components = find_all_components(schema);
        for child in child_components {
            if !used_components.contains(&child) {
                used_components.insert(child.clone());
                check_stack.insert(child);
            }
        }
    }

    components.schemas = components
        .schemas
        .iter()
        .filter(|(k, _)| used_components.contains(*k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    Ok(())
}

pub fn update_docs(is_test: bool) -> Result<()> {
    write_docs_file(
        is_test,
        RINGS_API_TEST_SPEC_FILE,
        RINGS_API_SPEC_FILE,
        PhotonApi::rings_method_api_specs(),
        true,
    )
}

fn write_docs_file(
    is_test: bool,
    test_file_name: &str,
    spec_file_name: &str,
    method_api_specs: Vec<OpenApiSpec>,
    filter_components: bool,
) -> Result<()> {
    let mut doc = ApiDoc::openapi();
    if let Some(mut components) = doc.components.take() {
        if filter_components {
            filter_unused_components_for_specs(&method_api_specs, &mut components)?;
        }
        components.schemas = components
            .schemas
            .iter()
            .map(|(k, v)| (k.clone(), fix_examples_for_all_of_references(v.clone())))
            .collect();
        doc.components = Some(components);
    }

    for spec in method_api_specs {
        let content = ContentBuilder::new()
            .schema(Some(request_schema(&spec.name, spec.request)))
            .build();
        let request_body = RequestBodyBuilder::new()
            .content(JSON_CONTENT_TYPE, content)
            .required(Some(Required::True))
            .build();
        let wrapped_response_schema =
            response_schema(fix_examples_for_all_of_references(spec.response));

        let responses = ResponsesBuilder::new().response(
            "200",
            ResponseBuilder::new().content(
                JSON_CONTENT_TYPE,
                ContentBuilder::new()
                    .schema(Some(wrapped_response_schema))
                    .build(),
            ),
        )
        .response("429", build_error_response("Exceeded rate limit."))
        .response("500", build_error_response("The server encountered an unexpected condition that prevented it from fulfilling the request."));
        let operation = OperationBuilder::new()
            .request_body(Some(request_body))
            .responses(responses)
            .build();
        let mut path_item = PathItem::new(HttpMethod::Post, operation);

        path_item.summary = Some(spec.name.clone());
        doc.paths
            .paths
            .insert(format!("/{method}", method = spec.name), path_item);
    }

    doc.servers = Some(vec![ServerBuilder::new()
        .url("https://devnet.helius-rpc.com?api-key=<api_key>".to_string())
        .build()]);
    let yaml = doc
        .to_yaml()
        .context("Failed to serialize OpenAPI schema")?;

    let path = match is_test {
        true => {
            let tmp_directory = std::env::temp_dir().join("photon-openapi");
            std::fs::create_dir_all(&tmp_directory).with_context(|| {
                format!(
                    "Failed to create OpenAPI temp directory {}",
                    tmp_directory.display()
                )
            })?;

            tmp_directory.join(test_file_name)
        }
        false => relative_project_path(&format!("src/openapi/specs/{spec_file_name}")),
    };

    std::fs::write(&path, yaml)
        .with_context(|| format!("Failed to write OpenAPI schema to {}", path.display()))?;

    let path_str = path
        .to_str()
        .with_context(|| format!("OpenAPI schema path is not valid UTF-8: {}", path.display()))?;
    let validate_result = std::process::Command::new("swagger-cli")
        .arg("validate")
        .arg(path_str)
        .output()
        .context("Failed to run swagger-cli validate")?;

    if !validate_result.status.success() {
        let stderr = String::from_utf8_lossy(&validate_result.stderr);
        bail!(
            "Failed to validate OpenAPI schema for {}. {}",
            spec_file_name,
            stderr
        );
    }

    Ok(())
}
