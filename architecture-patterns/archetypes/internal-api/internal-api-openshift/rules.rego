package archetype.webapp

# Approved databases for active-active (maintain as an array; update via Git)
approved_active_active_dbs := ["CockroachDB", "Cassandra"]

deny[msg] {
    # Check if app is active-active
    app := input.model.softwareSystems.app
    "active-active" in app.tags
    
    # Get database tech
    db := app.containers.database
    tech := db.technology
    
    # Validate against approved list
    not array_contains(approved_active_active_dbs, tech)
    msg := sprintf("Active-active deployment requires an approved database; '%s' is not in %v", [tech, approved_active_active_dbs])
}

# Helper function for array check
array_contains(arr, elem) {
    arr[_] == elem
}

# Existing rules remain, e.g., for missing components
deny[msg] {
    not input.model.softwareSystems.webApp.containers.database
    msg := "Missing required Database container"
}