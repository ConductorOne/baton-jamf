FROM gcr.io/distroless/static-debian11:nonroot
ENTRYPOINT ["/baton-jamf"]
COPY baton-jamf /