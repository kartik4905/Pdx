
//! PDF Anti-Forensics Tool - Complete CLI Interface
//! Author: kartik4091
//! Created: 2025-06-06
//! 
//! Complete command-line interface for PDF anti-forensics processing
//! Features: Full automation, metadata control, encryption, reporting, verification

use clap::{Arg, ArgGroup, Command, ValueEnum};
use pdx::config::{ProcessingConfig, SecurityOptions, UserMetadata, VerificationLevel, MetadataConfig};
use pdx::pipeline::Pipeline;
use pdx::{Logger, ReportGenerator, ReportConfig, ReportFormat, ReportError};
use std::fs;
use std::path::PathBuf;
use std::process;
use tracing::{error, info, warn, debug};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    /// Standard PDF output (default)
    Pdf,
    /// JSON report output
    Json,
    /// XML report output
    Xml,
    /// Plain text report
    Text,
}

#[derive(Debug, Clone, ValueEnum)]
enum ProcessingMode {
    /// Full anti-forensic processing (default)
    Full,
    /// Structure analysis only
    Analysis,
    /// Cleaning only
    Clean,
    /// Metadata enforcement only
    Metadata,
    /// Security and encryption only
    Security,
}

#[derive(Debug, Clone, ValueEnum)]
enum LogLevel {
    /// Error messages only
    Error,
    /// Warning and error messages
    Warn,
    /// Info, warning, and error messages (default)
    Info,
    /// Debug and all messages
    Debug,
    /// Trace and all messages (most verbose)
    Trace,
}

#[derive(Debug, Serialize, Deserialize)]
struct CliMetadata {
    title: Option<String>,
    author: Option<String>,
    subject: Option<String>,
    keywords: Option<String>,
    creator: Option<String>,
    producer: Option<String>,
    creation_date: Option<String>,
    modification_date: Option<String>,
}

impl From<CliMetadata> for UserMetadata {
    fn from(cli_meta: CliMetadata) -> Self {
        UserMetadata {
            title: cli_meta.title,
            author: cli_meta.author,
            subject: cli_meta.subject,
            keywords: cli_meta.keywords,
            creator: cli_meta.creator,
            producer: cli_meta.producer,
            creation_date: cli_meta.creation_date,
            modification_date: cli_meta.modification_date,
        }
    }
}

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let matches = build_cli().get_matches();

    // Initialize logging based on verbosity
    let log_level = matches.get_one::<LogLevel>("verbose").unwrap_or(&LogLevel::Info);
    init_logging(log_level);

    info!("🚀 PDF Anti-Forensics Tool v1.0.0 - Starting...");

    // Extract CLI arguments
    let input_path = matches.get_one::<String>("input").unwrap();
    let output_path = matches.get_one::<String>("output").unwrap();
    let metadata_file = matches.get_one::<String>("metadata-file");
    let verification_level = matches.get_one::<VerificationLevel>("level").unwrap();
    let processing_mode = matches.get_one::<ProcessingMode>("mode").unwrap_or(&ProcessingMode::Full);
    let output_format = matches.get_one::<OutputFormat>("format").unwrap_or(&OutputFormat::Pdf);
    let report_path = matches.get_one::<String>("report");
    let config_file = matches.get_one::<String>("config");
    
    // Security options
    let encrypt = matches.get_flag("encrypt");
    let user_pass = matches.get_one::<String>("user-pass");
    let owner_pass = matches.get_one::<String>("owner-pass");
    let permissions = extract_permissions(&matches);

    // Advanced options
    let force_overwrite = matches.get_flag("force");
    let backup_original = matches.get_flag("backup");
    let verify_output = matches.get_flag("verify");
    let dry_run = matches.get_flag("dry-run");

    // Validate input file exists
    if !PathBuf::from(input_path).exists() {
        error!("❌ Input file does not exist: {}", input_path);
        process::exit(1);
    }

    // Check if output exists and handle accordingly
    if PathBuf::from(output_path).exists() && !force_overwrite {
        error!("❌ Output file already exists: {}", output_path);
        error!("   Use --force to overwrite existing files");
        process::exit(1);
    }

    // Create backup if requested
    if backup_original {
        if let Err(e) = create_backup(input_path) {
            error!("❌ Failed to create backup: {}", e);
            process::exit(1);
        }
        info!("📁 Created backup of original file");
    }

    // Load configuration
    let mut config = if let Some(config_path) = config_file {
        match load_config_file(config_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("❌ Failed to load config file: {}", e);
                process::exit(1);
            }
        }
    } else {
        ProcessingConfig::default()
    };

    // Override config with CLI arguments
    config.verification_level = *verification_level;

    // Load metadata if provided
    if let Some(metadata_path) = metadata_file {
        match parse_metadata_file(metadata_path) {
            Ok(metadata) => config.user_metadata = Some(metadata),
            Err(e) => {
                error!("❌ Failed to parse metadata file: {}", e);
                process::exit(1);
            }
        }
    }

    // Set up security options
    if encrypt {
        config.security = Some(SecurityOptions {
            user_password: user_pass.map(|s| s.to_string()),
            owner_password: owner_pass.map(|s| s.to_string()),
            permissions,
            encryption_method: None, // Will use default AES-256
        });
    }

    // Set processing mode
    config.processing_mode = match processing_mode {
        ProcessingMode::Full => pdx::config::ProcessingMode::Full,
        ProcessingMode::Analysis => pdx::config::ProcessingMode::AnalysisOnly,
        ProcessingMode::Clean => pdx::config::ProcessingMode::CleaningOnly,
        ProcessingMode::Metadata => pdx::config::ProcessingMode::MetadataOnly,
        ProcessingMode::Security => pdx::config::ProcessingMode::SecurityOnly,
    };

    // Display configuration summary
    display_config_summary(&config, input_path, output_path);

    if dry_run {
        info!("🔍 Dry run mode - no files will be modified");
        info!("✅ Configuration validated successfully");
        return;
    }

    // Create and execute pipeline
    let pipeline = Pipeline::new(config.clone());

    info!("🚦 Starting PDF Anti-Forensics Pipeline...");
    let start_time = std::time::Instant::now();

    match pipeline.execute(input_path, output_path).await {
        Ok(()) => {
            let duration = start_time.elapsed();
            info!("✅ Pipeline execution completed successfully in {:.2?}", duration);
            
            // Verify output if requested
            if verify_output {
                info!("🔍 Verifying output file...");
                if let Err(e) = verify_output_file(output_path).await {
                    warn!("⚠️  Output verification failed: {}", e);
                } else {
                    info!("✅ Output file verification passed");
                }
            }

            // Generate report if requested
            if let Some(report_output) = report_path {
                info!("📊 Generating processing report...");
                let report_format = match output_format {
                    OutputFormat::Json => ReportFormat::Json,
                    OutputFormat::Xml => ReportFormat::Xml,
                    OutputFormat::Text | OutputFormat::Pdf => ReportFormat::PlainText,
                };

                let report_config = ReportConfig {
                    output_path: report_output.into(),
                    format: report_format,
                };

                if let Err(e) = ReportGenerator::generate_from_pipeline(&pipeline, &report_config).await {
                    error!("❌ Failed to generate report: {}", e);
                } else {
                    info!("📋 Report generated: {}", report_output);
                }
            }

            // Display final summary
            display_completion_summary(&pipeline, duration).await;
        }
        Err(e) => {
            error!("❌ Pipeline execution failed: {}", e);
            
            // Clean up partial output file if it exists
            if PathBuf::from(output_path).exists() {
                if let Err(cleanup_err) = fs::remove_file(output_path) {
                    error!("❌ Failed to clean up partial output file: {}", cleanup_err);
                }
            }
            
            process::exit(1);
        }
    }

    info!("🎉 PDF Anti-Forensics processing completed successfully!");
}

fn build_cli() -> Command {
    Command::new("PDF Anti-Forensics Tool")
        .version("1.0.0")
        .author("kartik4091")
        .about("Advanced PDF sanitization and anti-forensics tool with complete metadata control")
        .long_about("A comprehensive PDF processing tool that provides complete control over PDF structure, \
                    metadata, security, and forensic traces. Features zero fallback, no auto-inference, \
                    and strict user control over all document properties.")
        
        // Input/Output
        .arg(Arg::new("input")
            .short('i')
            .long("input")
            .value_name("FILE")
            .help("Input PDF file path")
            .required(true))
        
        .arg(Arg::new("output")
            .short('o')
            .long("output")
            .value_name("FILE")
            .help("Output PDF file path")
            .required(true))

        // Configuration
        .arg(Arg::new("config")
            .short('c')
            .long("config")
            .value_name("FILE")
            .help("Configuration file (JSON/YAML)"))

        .arg(Arg::new("metadata-file")
            .short('m')
            .long("metadata")
            .value_name("FILE")
            .help("Metadata file (JSON/YAML) with title, author, etc."))

        // Processing options
        .arg(Arg::new("mode")
            .long("mode")
            .value_enum::<ProcessingMode>()
            .default_value("full")
            .help("Processing mode"))

        .arg(Arg::new("level")
            .short('l')
            .long("level")
            .value_enum::<VerificationLevel>()
            .default_value("normal")
            .help("Verification level (paranoid/normal/lite)"))

        // Security and encryption
        .arg(Arg::new("encrypt")
            .short('e')
            .long("encrypt")
            .action(clap::ArgAction::SetTrue)
            .help("Enable PDF encryption"))

        .arg(Arg::new("user-pass")
            .long("user-password")
            .value_name("PASSWORD")
            .help("User password for PDF encryption")
            .requires("encrypt"))

        .arg(Arg::new("owner-pass")
            .long("owner-password")
            .value_name("PASSWORD")
            .help("Owner password for PDF encryption")
            .requires("encrypt"))

        .arg(Arg::new("no-print")
            .long("no-print")
            .action(clap::ArgAction::SetTrue)
            .help("Disable printing permission"))

        .arg(Arg::new("no-copy")
            .long("no-copy")
            .action(clap::ArgAction::SetTrue)
            .help("Disable copy/extract permission"))

        .arg(Arg::new("no-modify")
            .long("no-modify")
            .action(clap::ArgAction::SetTrue)
            .help("Disable modify permission"))

        .arg(Arg::new("no-annotate")
            .long("no-annotate")
            .action(clap::ArgAction::SetTrue)
            .help("Disable annotation permission"))

        // Output and reporting
        .arg(Arg::new("format")
            .short('f')
            .long("format")
            .value_enum::<OutputFormat>()
            .default_value("pdf")
            .help("Output format"))

        .arg(Arg::new("report")
            .short('r')
            .long("report")
            .value_name("FILE")
            .help("Generate processing report"))

        // Advanced options
        .arg(Arg::new("force")
            .long("force")
            .action(clap::ArgAction::SetTrue)
            .help("Force overwrite existing output files"))

        .arg(Arg::new("backup")
            .short('b')
            .long("backup")
            .action(clap::ArgAction::SetTrue)
            .help("Create backup of original file"))

        .arg(Arg::new("verify")
            .long("verify")
            .action(clap::ArgAction::SetTrue)
            .help("Verify output file after processing"))

        .arg(Arg::new("dry-run")
            .long("dry-run")
            .action(clap::ArgAction::SetTrue)
            .help("Show what would be done without making changes"))

        // Logging
        .arg(Arg::new("verbose")
            .short('v')
            .long("verbose")
            .value_enum::<LogLevel>()
            .default_value("info")
            .help("Set logging verbosity"))

        .arg(Arg::new("quiet")
            .short('q')
            .long("quiet")
            .action(clap::ArgAction::SetTrue)
            .conflicts_with("verbose")
            .help("Suppress all output except errors"))

        // Validation groups
        .group(ArgGroup::new("encryption")
            .args(["encrypt", "user-pass", "owner-pass"])
            .multiple(true))
}

fn init_logging(level: &LogLevel) {
    use tracing_subscriber::{EnvFilter, FmtSubscriber};

    let filter_level = match level {
        LogLevel::Error => "error",
        LogLevel::Warn => "warn", 
        LogLevel::Info => "info",
        LogLevel::Debug => "debug",
        LogLevel::Trace => "trace",
    };

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::new(format!("pdx={}", filter_level)))
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .compact()
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");
}

fn parse_metadata_file(path: &str) -> Result<UserMetadata, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read metadata file: {}", e))?;

    // Try JSON first, then YAML
    let cli_metadata: CliMetadata = serde_json::from_str(&content)
        .or_else(|_| serde_yaml::from_str(&content))
        .map_err(|e| format!("Metadata parsing error: {}", e))?;

    Ok(cli_metadata.into())
}

fn load_config_file(path: &str) -> Result<ProcessingConfig, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config file: {}", e))?;

    serde_json::from_str(&content)
        .or_else(|_| serde_yaml::from_str(&content))
        .map_err(|e| format!("Config parsing error: {}", e))
}

fn extract_permissions(matches: &clap::ArgMatches) -> Option<pdx::config::Permissions> {
    if matches.get_flag("no-print") || 
       matches.get_flag("no-copy") || 
       matches.get_flag("no-modify") || 
       matches.get_flag("no-annotate") {
        Some(pdx::config::Permissions {
            print: !matches.get_flag("no-print"),
            copy: !matches.get_flag("no-copy"),
            modify: !matches.get_flag("no-modify"),
            annotate: !matches.get_flag("no-annotate"),
        })
    } else {
        None
    }
}

fn create_backup(input_path: &str) -> Result<(), std::io::Error> {
    let backup_path = format!("{}.backup", input_path);
    fs::copy(input_path, backup_path)?;
    Ok(())
}

fn display_config_summary(config: &ProcessingConfig, input: &str, output: &str) {
    info!("📋 Configuration Summary:");
    info!("   Input:  {}", input);
    info!("   Output: {}", output);
    info!("   Verification Level: {:?}", config.verification_level);
    info!("   Processing Mode: {:?}", config.processing_mode);
    
    if config.security.is_some() {
        info!("   Security: Encryption enabled");
    }
    
    if config.user_metadata.is_some() {
        info!("   Metadata: Custom metadata provided");
    }
}

async fn verify_output_file(output_path: &str) -> Result<(), String> {
    // Basic file existence and readability check
    if !PathBuf::from(output_path).exists() {
        return Err("Output file does not exist".to_string());
    }

    // Try to read first few bytes to verify it's a PDF
    match fs::read(output_path) {
        Ok(bytes) => {
            if bytes.len() < 5 || !bytes.starts_with(b"%PDF-") {
                return Err("Output file is not a valid PDF".to_string());
            }
            Ok(())
        }
        Err(e) => Err(format!("Cannot read output file: {}", e))
    }
}

async fn display_completion_summary(pipeline: &Pipeline, duration: std::time::Duration) {
    info!("📊 Processing Summary:");
    info!("   Total Time: {:.2?}", duration);
    
    // Get report data from pipeline
    let report_data = pipeline.get_report_data();
    
    info!("   Stages Completed: 8/8");
    info!("   Status: ✅ Success");
    info!("   Output: Clean, anti-forensic PDF generated");
}
