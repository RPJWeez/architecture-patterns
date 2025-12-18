package archetype.webapp

import rego.v1

# Approved databases for active-active (maintain as an array; update via Git)
approved_active_active_dbs := ["CockroachDB", "Cassandra"]

deny contains msg if {
    # Check if app is active-active
    app := input.model.softwareSystems.app
    "active-active" in app.tags
    
    # Get database tech
    db := app.containers.database
    tech := db.technology  # Or check db.tags if tech is stored there
    
    # Validate against approved list
    not tech in approved_active_active_dbs
    msg := sprintf("Active-active deployment requires an approved database; '%s' is not in %v", [tech, approved_active_active_dbs])
}

# Existing rule for missing database
deny contains msg if {
    not input.model.softwareSystems.app.containers.database  # Consistent path
    msg := "Missing required Database container"
}