use std::fs::File;
use std::io::{Write, BufWriter};
use zip::write::{ZipWriter, FileOptions};
use zip::CompressionMethod;
use chrono::{DateTime, Utc};
use serde_json;
use sha2::{Sha256, Digest};

pub struct AuditPackExporter {
    output_path: String,
}

#[derive(serde::Serialize)]
struct AuditMetadata {
    generated_at: DateTime<Utc>,
    version: String,
    checksums: Vec<FileChecksum>,
}

#[derive(serde::Serialize)]
struct FileChecksum {
    filename: String,
    sha256: String,
}

impl AuditPackExporter {
    pub fn new(output_path: String) -> Self {
        Self { output_path }
    }
    
    pub async fn generate_audit_pack(
        &self,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
        _tenant_id: Option<String>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let file = File::create(&self.output_path)?;
        let mut zip = ZipWriter::new(BufWriter::new(file));
        
        let options: zip::write::FileOptions<'_, ()> = FileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o644);
        
        let mut metadata = AuditMetadata {
            generated_at: Utc::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            checksums: Vec::new(),
        };
        
        // 1. Export SBOM
        if let Ok(sbom) = std::fs::read_to_string("sbom.cyclonedx.json") {
            zip.start_file("sbom.cyclonedx.json", options)?;
            zip.write_all(sbom.as_bytes())?;
            metadata.checksums.push(FileChecksum {
                filename: "sbom.cyclonedx.json".to_string(),
                sha256: Self::hash_content(sbom.as_bytes()),
            });
        }
        
        // 2. Export STH checkpoints
        let checkpoints = self.export_checkpoints(start_date, end_date).await?;
        zip.start_file("checkpoints.json", options)?;
        let checkpoint_json = serde_json::to_string_pretty(&checkpoints)?;
        zip.write_all(checkpoint_json.as_bytes())?;
        metadata.checksums.push(FileChecksum {
            filename: "checkpoints.json".to_string(),
            sha256: Self::hash_content(checkpoint_json.as_bytes()),
        });
        
        // 3. Export witness signatures
        let witness_sigs = self.export_witness_signatures(start_date, end_date).await?;
        zip.start_file("witness_signatures.json", options)?;
        let witness_json = serde_json::to_string_pretty(&witness_sigs)?;
        zip.write_all(witness_json.as_bytes())?;
        metadata.checksums.push(FileChecksum {
            filename: "witness_signatures.json".to_string(),
            sha256: Self::hash_content(witness_json.as_bytes()),
        });
        
        // 4. Export random inclusion proofs
        let proofs = self.export_random_proofs(256).await?;
        zip.start_file("inclusion_proofs.json", options)?;
        let proofs_json = serde_json::to_string_pretty(&proofs)?;
        zip.write_all(proofs_json.as_bytes())?;
        metadata.checksums.push(FileChecksum {
            filename: "inclusion_proofs.json".to_string(),
            sha256: Self::hash_content(proofs_json.as_bytes()),
        });
        
        // 5. Export policy snapshots
        let policies = self.export_policy_snapshots(tenant_id).await?;
        zip.start_file("policy_snapshots.json", options)?;
        let policies_json = serde_json::to_string_pretty(&policies)?;
        zip.write_all(policies_json.as_bytes())?;
        metadata.checksums.push(FileChecksum {
            filename: "policy_snapshots.json".to_string(),
            sha256: Self::hash_content(policies_json.as_bytes()),
        });
        
        // 6. Export key catalog
        let key_catalog = self.export_key_catalog().await?;
        zip.start_file("key_catalog.json", options)?;
        let catalog_json = serde_json::to_string_pretty(&key_catalog)?;
        zip.write_all(catalog_json.as_bytes())?;
        metadata.checksums.push(FileChecksum {
            filename: "key_catalog.json".to_string(),
            sha256: Self::hash_content(catalog_json.as_bytes()),
        });
        
        // 7. Add proof PDFs if available
        for pdf in std::fs::read_dir("formal/proofs").unwrap_or_else(|_| {
            std::fs::read_dir(".").unwrap()
        }) {
            if let Ok(entry) = pdf {
                if entry.path().extension().map_or(false, |ext| ext == "pdf") {
                    let filename = entry.file_name().to_string_lossy().to_string();
                    let content = std::fs::read(entry.path())?;
                    zip.start_file(&format!("proofs/{}", filename), options)?;
                    zip.write_all(&content)?;
                    metadata.checksums.push(FileChecksum {
                        filename: format!("proofs/{}", filename),
                        sha256: Self::hash_content(&content),
                    });
                }
            }
        }
        
        // 8. Add metadata file
        zip.start_file("METADATA.json", options)?;
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        zip.write_all(metadata_json.as_bytes())?;
        
        // Finalize ZIP
        zip.finish()?;
        
        Ok(self.output_path.clone())
    }
    
    fn hash_content(content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        hex::encode(hasher.finalize())
    }
    
    async fn export_checkpoints(
        &self,
        _start: DateTime<Utc>,
        _end: DateTime<Utc>,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        // Implementation would query transparency log
        Ok(vec![])
    }
    
    async fn export_witness_signatures(
        &self,
        _start: DateTime<Utc>,
        _end: DateTime<Utc>,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        // Implementation would query witness storage
        Ok(vec![])
    }
    
    async fn export_random_proofs(
        &self,
        _count: usize,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        // Implementation would generate random inclusion proofs
        Ok(vec![])
    }
    
    async fn export_policy_snapshots(
        &self,
        _tenant_id: Option<String>,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        // Implementation would export policy history
        Ok(vec![])
    }
    
    async fn export_key_catalog(&self) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        // Implementation would export key catalog
        Ok(serde_json::json!({
            "keys": []
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    
    #[tokio::test]
    async fn test_audit_pack_creation() {
        let temp_file = NamedTempFile::new().unwrap();
        let exporter = AuditPackExporter::new(
            temp_file.path().to_string_lossy().to_string()
        );
        
        let result = exporter.generate_audit_pack(
            Utc::now() - chrono::Duration::days(7),
            Utc::now(),
            Some("tenant123".to_string()),
        ).await;
        
        assert!(result.is_ok());
    }
}
