# parsedmarc Helm chart

This chart packages the private LifeguardPress Kubernetes deployment for
parsedmarc. It creates the parsedmarc Deployment and ConfigMap, the three
ExternalSecret resources used by the workload, and an optional Kibana saved
objects import hook.

The repository's `skaffold.yaml` deploys this chart to the production GKE
cluster from the `master` GitHub Actions workflow after the container image is
published.

The chart does not contain secret values. It expects the External Secrets
Operator and the configured `ClusterSecretStore` to already exist in the
cluster.

Install it into the existing `dmarc` namespace with:

```sh
helm upgrade --install parsedmarc ./charts/parsedmarc \
  --namespace dmarc \
  --create-namespace
```

After the External Secrets Operator has populated the Kibana credentials,
run the saved objects import with:

```sh
helm upgrade parsedmarc ./charts/parsedmarc \
  --namespace dmarc \
  --set dashboardImport.enabled=true
```

For production, pin `image.tag` to a release or image digest and set
`dashboardImport.enabled=false` after the import has completed.
