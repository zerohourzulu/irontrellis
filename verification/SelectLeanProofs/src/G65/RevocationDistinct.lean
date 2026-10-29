import AuthorityModel.Bounds

namespace Authority.G64

private theorem erase_loop_length (xs acc : List Id) :
    (List.eraseDupsBy.loop (· == ·) xs acc).length ≤ xs.length + acc.length := by
  induction xs generalizing acc with
  | nil => simp [List.eraseDupsBy.loop]
  | cons x xs ih =>
    simp only [List.eraseDupsBy.loop]
    split
    · have h := ih acc
      simp only [List.length_cons]
      omega
    · have h := ih (x :: acc)
      simp only [List.length_cons] at h ⊢
      omega

private theorem erase_loop_full (xs acc : List Id)
    (full : (List.eraseDupsBy.loop (· == ·) xs acc).length = xs.length + acc.length) :
    xs.Nodup ∧ ∀ x ∈ xs, x ∉ acc := by
  induction xs generalizing acc with
  | nil => simp
  | cons x xs ih =>
    simp only [List.eraseDupsBy.loop] at full
    split at full
    · have h := erase_loop_length xs acc
      simp only [List.length_cons] at full
      omega
    · rename_i fresh
      have hx : x ∉ acc := by
        have each : ∀ y ∈ acc, x ≠ y := by simpa using fresh
        exact fun member => each x member rfl
      have hfull : (List.eraseDupsBy.loop (· == ·) xs (x :: acc)).length =
          xs.length + (x :: acc).length := by
        simpa only [List.length_cons, Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using full
      obtain ⟨nd, avoids⟩ := ih (x :: acc) hfull
      constructor
      · apply List.nodup_cons.mpr
        exact ⟨fun mem => avoids x mem (by simp), nd⟩
      · intro y mem
        rcases List.mem_cons.mp mem with rfl | mem
        · exact hx
        · exact fun ha => avoids y mem (by simp [ha])

/-- The executable length-based duplicate check entails ordinary uniqueness. -/
theorem distinct_nodup (xs : List Id) (h : distinct xs = true) : xs.Nodup := by
  have originalLen : xs.length = xs.eraseDups.length := by
    simpa only [distinct, beq_iff_eq] using h
  have len := originalLen.symm
  exact (erase_loop_full xs [] (by simpa [List.eraseDups, List.eraseDupsBy] using len)).1

theorem corpus_grant_ids_nodup (c : Corpus) (wf : corpusStatus c = .valid) :
    (c.permissions.map (·.authorityId) ++ c.prohibitions.map (·.authorityId)).Nodup := by
  unfold corpusStatus at wf
  have initial := (Authority.statuses_valid _ _ wf).1
  split at initial
  · contradiction
  · split at initial
    · contradiction
    · rename_i distinctIds
      apply distinct_nodup
      simpa using distinctIds

theorem permission_prohibition_ids_disjoint (c : Corpus) (wf : corpusStatus c = .valid)
    (g : Permission) (hg : g ∈ c.permissions) (p : Prohibition) (hp : p ∈ c.prohibitions) :
    g.authorityId ≠ p.authorityId := by
  have cross := (List.nodup_append.mp (corpus_grant_ids_nodup c wf)).2.2
  exact cross g.authorityId (List.mem_map.mpr ⟨g, hg, rfl⟩)
    p.authorityId (List.mem_map.mpr ⟨p, hp, rfl⟩)

#print axioms distinct_nodup
#print axioms corpus_grant_ids_nodup
#print axioms permission_prohibition_ids_disjoint
end Authority.G64
