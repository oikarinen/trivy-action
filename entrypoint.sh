#!/bin/bash
set -euo pipefail

while getopts "a:b:c:d:e:f:g:h:i:j:k:l:m:n:o:p:q:r:s:t:u:v:x:z:" o; do
  # Remove leading whitespace and trailing \r and whitespace
  OPTARG=$(echo "${OPTARG}" | tr -d '\r' | xargs)
  if [ -z "${OPTARG}" ]; then
    continue
  fi
  case "${o}" in
      a)
        scanType="$OPTARG"
      ;;
      b)
        format="$OPTARG"
      ;;
      c)
        ARGS+=( "--template" "$OPTARG" )
      ;;
      d)
        ARGS+=( "--exit-code" "$OPTARG" )
        SARIF_ARGS+=( "--exit-code" "$OPTARG" )
      ;;
      e)
        [ "$OPTARG" == "true" ] && ignoreUnfixed="--ignore-unfixed"
      ;;
      f)
        vulnType+=( "--vuln-type" "$OPTARG" )
      ;;
      g)
        ARGS+=( "--severity" "$OPTARG" )
      ;;
      h)
        ARGS+=( "--output" "$OPTARG" )
      ;;
      i)
        imageRef="$OPTARG"
      ;;
      j)
        scanRef="$OPTARG"
      ;;
      k)
        for i in ${OPTARG//,/ }
        do
            ARGS+=("--skip-dirs" "$i")
            SARIF_ARGS+=("--skip-dirs" "$i")
        done
      ;;
      l)
        input="--input $OPTARG"
      ;;
      m)
        GLOBAL_ARGS=("--cache-dir" "$OPTARG")
      ;;
      n)
        ARGS+=( "--timeout" "$OPTARG" )
        SARIF_ARGS+=( "--timeout" "$OPTARG" )
      ;;
      o)
        ARGS+=( "--ignore-policy" "$OPTARG" )
        SARIF_ARGS+=( "--ignore-policy" "$OPTARG" )
      ;;
      p)
        if [ "$OPTARG" == "true" ]; then
            ARGS+=( "--no-progress" )
            SARIF_ARGS+=( "--no-progress" )
        fi
      ;;
      q)
        for i in ${OPTARG//,/ }
        do
            ARGS+=("--skip-files" "$i")
            SARIF_ARGS+=("--skip-files" "$i")
        done
      ;;
      r)
        [ "$OPTARG" == "true" ] && ARGS+=( "--list-all-pkgs" )
      ;;
      s)
        ARGS+=( "--scanners" "$OPTARG" )
        SARIF_ARGS+=( "--scanners" "$OPTARG" )
      ;;
      t)
        for f in ${OPTARG//,/ }
        do
            if [ -f "$f" ]; then
                echo "::notice ::Found ignorefile '${f}':"
                tee -a ./trivyignores < "$f"
            else
                echo "::error ::ERROR: cannot find ignorefile '${f}'."
                exit 1
            fi
        done
        ARGS+=( "--ignorefile" "./trivyignores" )
      ;;
      u)
        githubPAT="$OPTARG"
      ;;
      v)
        trivyConfig="$OPTARG"
      ;;
      x)
        ARGS+=( "--tf-vars" "$OPTARG" )
      ;;
      z)
        limitSeveritiesForSARIF="$OPTARG"
      ;;
      *)
        echo "::error ::Invalid option: ${o}"
        exit 2
      ;;
 esac
done

artifactRef="${imageRef-}"
case "${scanType-}" in
    repo|fs|filesystem|rootfs)
        artifactRef="${scanRef-}"
        ARGS+=("${ignoreUnfixed-}" "${vulnType[@]-}")
        SARIF_ARGS+=("${ignoreUnfixed-}" "${vulnType[@]-}")
    ;;
    config)
        artifactRef="${scanRef-}"
    ;;
    sbom)
        artifactRef="${scanRef-}"
        ARGS+=("${ignoreUnfixed-}")
        SARIF_ARGS+=("${ignoreUnfixed-}")
    ;;
esac

if [ "${input-}" ]; then
  artifactRef="$input"
fi

# To make sure that upload GitHub Dependency Snapshot succeeds, disable the script that fails first.
set +e
if [ "${format-}" == "sarif" ] && [ "${limitSeveritiesForSARIF-}" != "true" ]; then
  # SARIF is special. We output all vulnerabilities,
  # regardless of severity level specified in this report.
  # This is a feature, not a bug :)
  echo "::notice ::Building SARIF report"
  echo -n "::debug ::trivy --quiet ${scanType-} --format ${format-} ${SARIF_ARGS[*]-} "
  echo "${ignoreUnfixed-} ${vulnType[*]-} ${artifactRef-}"
  trivy --quiet "${scanType-}" --format "${format-}" "${SARIF_ARGS[@]-}" "${artifactRef-}"
elif [ "${trivyConfig-}" ]; then
  echo "Running Trivy with trivy.yaml config from: $trivyConfig"
  echo "::debug ::trivy --config ${trivyConfig-} ${scanType-} ${artifactRef-}"
  trivy --config "${trivyConfig-}" "${scanType-}" "${artifactRef-}"
else
  echo "Running trivy"
  echo "::notice ::Running trivy"
  echo -n "::debug :: trivy ${GLOBAL_ARGS[*]-} ${scanType-} --format ${format-} ${ARGS[*]-} "
  echo "${artifactRef-}"
  trivy "${GLOBAL_ARGS[@]-}" "${scanType-}" --format "${format-}" "${ARGS[@]-}" "${artifactRef-}"
fi
returnCode=$?

set -e
if [ "${format-}" == "github" ]; then
  if [ "${githubPAT-}" != "" ]; then
    printf "\n ::notice ::Uploading GitHub Dependency Snapshot"
    curl -H 'Accept: application/vnd.github+json' -H "Authorization: token $githubPAT" \
        "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/dependency-graph/snapshots" -d "@./${output-}"
  else
    printf "\n ::error ::Failing GitHub Dependency Snapshot. Missing github-pat"
    exit 1
  fi
fi

exit $returnCode
