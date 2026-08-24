				for fd in table_fields.iter() {
					// Loop over each field in document
					for k in out.each(&fd.name).iter() {
						// Process the field permissions
						match &fd.select_permission {
							catalog::Permission::Full => (),
							catalog::Permission::None => out.del(stk, ctx, opt, k).await?,
							catalog::Permission::Specific(e) => {
								// Disable permissions
								let opt = &opt.new_with_perms(false);
								// Get the current value
								let val = Arc::new(self.current.doc.as_ref().pick(k));
								// Configure the context
								let mut ctx = Context::new_child(ctx);
								ctx.add_value("value", val);
								let ctx = ctx.freeze();
								// Process the PERMISSION clause
								if !stk
									.run(|stk| e.compute(stk, &ctx, opt, Some(&self.current)))
									.await
									.catch_return()?
									.is_truthy()
								{
									out.cut(k);
								}
							}
						}
					}
				}
