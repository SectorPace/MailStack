# MailStack Control Plane -- single declaration of the product version.
#
# It lives in its own leaf module because __init__ imports the dispatcher, which
# imports backup/telemetry, which need the version. Importing it back from the
# package root at that point hits a partially initialised module.

__version__ = "0.8.0-beta.7"
