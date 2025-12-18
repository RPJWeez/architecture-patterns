package archetype.webapp

import rego.v1

# Approved databases for active-active
approved_active_active_dbs := ["CockroachDB", "Cassandra"]

# Helper: Find the main app software system (by DSL identifier "app")
app := sys if {
    some sys in input.model.softwareSystems
    sys.properties["structurizr.dsl.identifier"] == "app"
}

# Helper: Find the database container (by DSL identifier "database")
database := cont if {
    some cont in app.containers
    cont.properties["structurizr.dsl.identifier"] == "database"
}

# Rule: Missing required Database container
deny contains msg if {
    not database
    msg := "Missing required Database container"
}

# Rule: Active-active requires approved DB technology
deny contains msg if {
    # Check if app has "active-active" tag (tags is a comma-separated string)
    contains(app.tags, "active-active")
    
    tech := database.technology
    
    not tech in approved_active_active_dbs
    msg := sprintf("Active-active deployment requires an approved database; '%s' is not in %v", [tech, approved_active_active_dbs])
}