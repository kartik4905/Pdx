//! Structure handling modules for PDF structure analysis and repair
//! Author: kartik4091

pub mod structure_handler;
pub mod cross_ref_handler;
pub mod linearization_handler;

pub use structure_handler::StructureHandler;
pub use cross_ref_handler::CrossRefHandler;
pub use linearization_handler::LinearizationHandler;